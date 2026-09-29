import { execFile } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import type {
  GitHubPrPublication,
  GitIntegrationArtifact,
  TaskSpec,
} from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";

const execFileAsync = promisify(execFile);
export const GITHUB_API_VERSION = "2026-03-10";
const API_BASE = "https://api.github.com";
const SHA40 = /^[0-9a-f]{40}$/;

export interface GitHubInstallationCredential {
  token: string;
  expires_at: string;
  installation_id: number;
}

export interface GitHubInstallationTokenProvider {
  issueForRepo(repoId: string): Promise<GitHubInstallationCredential>;
}

export interface ExactCommitPusher {
  push(input: {
    repoId: string;
    branch: string;
    commitSha: string;
    workspace: string;
    token: string;
  }): Promise<void>;
}

export type PublishedPullRequest = GitHubPrPublication;

function parseRepoId(repoId: string): { owner: string; repo: string } {
  const match = /^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/.exec(repoId);
  if (!match) {
    throw new ControllerError(
      "REPO_SOURCE_INVALID",
      "repo_id is not a safe GitHub owner/repo id",
    );
  }
  return { owner: match[1]!, repo: match[2]! };
}

export function integrationBranchName(artifact: GitIntegrationArtifact): string {
  if (!/^[0-9a-f]{64}$/.test(artifact.candidate_hash)) {
    throw new ControllerError(
      "CANDIDATE_HASH_INVALID",
      "Integration branch requires canonical candidate hash",
    );
  }
  return "awf/candidate-" + artifact.candidate_hash.slice(0, 24);
}

function encodeRef(ref: string): string {
  return ref.split("/").map(encodeURIComponent).join("/");
}

interface RefResponse {
  ref: string;
  object: { type: string; sha: string };
}

interface PullResponse {
  number: number;
  html_url: string;
  state: string;
  draft?: boolean;
  merged?: boolean;
  merge_commit_sha?: string | null;
  head: { ref: string; sha: string };
  base: { ref: string; sha: string };
}

export interface GitHubCheckRunObservation {
  id: number;
  name: string;
  status: string;
  conclusion: string | null;
  head_sha: string;
}

interface GitHubCheckRunsResponse {
  total_count: number;
  check_runs: GitHubCheckRunObservation[];
}

export interface GitHubCommitStatusObservation {
  id: number;
  state: string;
  context: string;
}

export interface GitHubCombinedStatusObservation {
  state: string;
  sha: string;
  total_count: number;
  statuses: GitHubCommitStatusObservation[];
}

export class GitHubRestApi {
  readonly #token: string;
  readonly #fetch: typeof fetch;

  constructor(token: string, fetchImpl: typeof fetch = fetch) {
    if (!token) {
      throw new ControllerError(
        "GITHUB_TOKEN_INVALID",
        "GitHub installation token is empty",
      );
    }
    this.#token = token;
    this.#fetch = fetchImpl;
  }

  async #request<T>(
    method: string,
    path: string,
    body?: unknown,
    allow404 = false,
  ): Promise<T | null> {
    const response = await this.#fetch(API_BASE + path, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: "Bearer " + this.#token,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "autonomous-worker-controller/0.1",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (allow404 && response.status === 404) return null;
    if (!response.ok) {
      const payload = (await response.text()).slice(0, 4096);
      throw new ControllerError(
        "GITHUB_API_FAILED",
        "GitHub REST request failed",
        {
          method,
          path,
          status: response.status,
          response: payload,
        },
      );
    }
    if (response.status === 204) return null;
    return (await response.json()) as T;
  }

  async getBranchHead(repoId: string, branch: string): Promise<string | null> {
    const { owner, repo } = parseRepoId(repoId);
    const path =
      "/repos/" +
      encodeURIComponent(owner) +
      "/" +
      encodeURIComponent(repo) +
      "/git/ref/" +
      encodeRef("heads/" + branch);
    const value = await this.#request<RefResponse>(
      "GET",
      path,
      undefined,
      true,
    );
    if (value === null) return null;
    const sha = value.object?.sha?.toLowerCase();
    if (value.object?.type !== "commit" || !SHA40.test(sha)) {
      throw new ControllerError(
        "GITHUB_REF_INVALID",
        "GitHub branch ref did not resolve to a canonical commit SHA",
      );
    }
    return sha;
  }

  async listOpenPulls(
    repoId: string,
    branch: string,
    baseRef: string,
  ): Promise<PullResponse[]> {
    const { owner, repo } = parseRepoId(repoId);
    const query = new URLSearchParams({
      state: "open",
      head: owner + ":" + branch,
      base: baseRef,
      per_page: "10",
    });
    const path =
      "/repos/" +
      encodeURIComponent(owner) +
      "/" +
      encodeURIComponent(repo) +
      "/pulls?" +
      query.toString();
    const value = await this.#request<PullResponse[]>("GET", path);
    return value ?? [];
  }

  async createPull(input: {
    repoId: string;
    branch: string;
    baseRef: string;
    title: string;
    body: string;
  }): Promise<PullResponse> {
    const { owner, repo } = parseRepoId(input.repoId);
    const path =
      "/repos/" +
      encodeURIComponent(owner) +
      "/" +
      encodeURIComponent(repo) +
      "/pulls";
    const value = await this.#request<PullResponse>("POST", path, {
      title: input.title,
      body: input.body,
      head: input.branch,
      base: input.baseRef,
      draft: false,
      maintainer_can_modify: false,
    });
    if (!value) {
      throw new ControllerError(
        "GITHUB_PR_CREATE_FAILED",
        "GitHub returned no pull request payload",
      );
    }
    return value;
  }

  async listCheckRuns(
    repoId: string,
    commitSha: string,
  ): Promise<GitHubCheckRunObservation[]> {
    if (!SHA40.test(commitSha)) {
      throw new ControllerError(
        "GITHUB_COMMIT_SHA_INVALID",
        "Check-run lookup requires canonical commit SHA",
      );
    }
    const { owner, repo } = parseRepoId(repoId);
    const query = new URLSearchParams({ filter: "latest", per_page: "100" });
    const path =
      "/repos/" +
      encodeURIComponent(owner) +
      "/" +
      encodeURIComponent(repo) +
      "/commits/" +
      commitSha +
      "/check-runs?" +
      query.toString();
    const value = await this.#request<GitHubCheckRunsResponse>("GET", path);
    const runs = value?.check_runs ?? [];
    for (const run of runs) {
      const head = run.head_sha?.toLowerCase();
      if (!Number.isInteger(run.id) || run.id <= 0 || !run.name || !SHA40.test(head)) {
        throw new ControllerError(
          "GITHUB_CHECK_RUN_INVALID",
          "GitHub check-run payload is invalid",
        );
      }
      run.head_sha = head;
    }
    return runs;
  }

  async getCombinedStatus(
    repoId: string,
    commitSha: string,
  ): Promise<GitHubCombinedStatusObservation> {
    if (!SHA40.test(commitSha)) {
      throw new ControllerError(
        "GITHUB_COMMIT_SHA_INVALID",
        "Commit-status lookup requires canonical commit SHA",
      );
    }
    const { owner, repo } = parseRepoId(repoId);
    const path =
      "/repos/" +
      encodeURIComponent(owner) +
      "/" +
      encodeURIComponent(repo) +
      "/commits/" +
      commitSha +
      "/status";
    const value = await this.#request<GitHubCombinedStatusObservation>(
      "GET",
      path,
    );
    if (!value) {
      throw new ControllerError(
        "GITHUB_COMMIT_STATUS_INVALID",
        "GitHub returned no combined commit status payload",
      );
    }
    value.sha = value.sha.toLowerCase();
    if (!SHA40.test(value.sha)) {
      throw new ControllerError(
        "GITHUB_COMMIT_STATUS_INVALID",
        "GitHub combined commit status has invalid SHA",
      );
    }
    return value;
  }

  async mergePull(
    repoId: string,
    pullNumber: number,
    expectedHeadSha: string,
    mergeMethod: "squash" | "merge" | "rebase",
  ): Promise<{ sha: string; merged: true; message: string }> {
    if (!SHA40.test(expectedHeadSha)) {
      throw new ControllerError(
        "GITHUB_COMMIT_SHA_INVALID",
        "Pull-request merge requires canonical expected head SHA",
      );
    }
    const { owner, repo } = parseRepoId(repoId);
    const path =
      "/repos/" +
      encodeURIComponent(owner) +
      "/" +
      encodeURIComponent(repo) +
      "/pulls/" +
      String(pullNumber) +
      "/merge";
    const value = await this.#request<{
      sha: string;
      merged: boolean;
      message: string;
    }>("PUT", path, {
      sha: expectedHeadSha,
      merge_method: mergeMethod,
    });
    const sha = value?.sha?.toLowerCase() ?? "";
    if (!value || value.merged !== true || !SHA40.test(sha)) {
      throw new ControllerError(
        "GITHUB_MERGE_FAILED",
        "GitHub did not return a successful canonical merge result",
        { pullNumber, merged: value?.merged ?? null },
      );
    }
    return { sha, merged: true, message: value.message };
  }

  async getPull(repoId: string, pullNumber: number): Promise<PullResponse> {
    const { owner, repo } = parseRepoId(repoId);
    const path =
      "/repos/" +
      encodeURIComponent(owner) +
      "/" +
      encodeURIComponent(repo) +
      "/pulls/" +
      String(pullNumber);
    const value = await this.#request<PullResponse>("GET", path);
    if (!value) {
      throw new ControllerError(
        "GITHUB_PR_NOT_FOUND",
        "GitHub returned no pull request payload",
      );
    }
    return value;
  }
}

export class GitHubHttpsCommitPusher implements ExactCommitPusher {
  async push(input: {
    repoId: string;
    branch: string;
    commitSha: string;
    workspace: string;
    token: string;
  }): Promise<void> {
    const { owner, repo } = parseRepoId(input.repoId);
    if (!SHA40.test(input.commitSha)) {
      throw new ControllerError(
        "GIT_INTEGRATION_COMMIT_INVALID",
        "Push requires canonical integration commit SHA",
      );
    }

    const authRoot = mkdtempSync(join(tmpdir(), "awf-github-askpass-"));
    const askpass = join(authRoot, "askpass.sh");
    writeFileSync(
      askpass,
      [
        "#!/bin/sh",
        'case "$1" in',
        '  *Username*) printf \'%s\\n\' "x-access-token" ;;',
        '  *Password*) printf \'%s\\n\' "$AWF_GITHUB_INSTALLATION_TOKEN" ;;',
        "  *) exit 1 ;;",
        "esac",
        "",
      ].join("\n"),
      { mode: 0o700 },
    );
    chmodSync(askpass, 0o700);

    try {
      await execFileAsync(
        "/usr/bin/git",
        [
          "push",
          "--porcelain",
          "--no-verify",
          "https://github.com/" + owner + "/" + repo + ".git",
          input.commitSha + ":refs/heads/" + input.branch,
        ],
        {
          cwd: input.workspace,
          timeout: 120_000,
          maxBuffer: 4 * 1024 * 1024,
          env: {
            PATH: "/usr/bin:/bin",
            HOME: "/nonexistent",
            LANG: "C.UTF-8",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_TERMINAL_PROMPT: "0",
            GIT_ASKPASS_REQUIRE: "force",
            GIT_ASKPASS: askpass,
            AWF_GITHUB_INSTALLATION_TOKEN: input.token,
          },
        },
      );
    } catch (error) {
      const value = error as { stderr?: string; message?: string };
      throw new ControllerError(
        "GITHUB_PUSH_FAILED",
        "Trusted GitHub exact-commit push failed",
        {
          repoId: input.repoId,
          branch: input.branch,
          commitSha: input.commitSha,
          stderr: value.stderr?.slice(-4096) ?? "",
          cause: value.message ?? String(error),
        },
      );
    } finally {
      rmSync(authRoot, { recursive: true, force: true });
    }
  }
}

export interface GitHubPullRequestPublisherOptions {
  credentials: GitHubInstallationTokenProvider;
  fetch?: typeof fetch;
  pusher?: ExactCommitPusher;
  now?: () => Date;
}

export class GitHubPullRequestPublisher {
  readonly #credentials: GitHubInstallationTokenProvider;
  readonly #fetch: typeof fetch;
  readonly #pusher: ExactCommitPusher;
  readonly #now: () => Date;

  constructor(options: GitHubPullRequestPublisherOptions) {
    this.#credentials = options.credentials;
    this.#fetch = options.fetch ?? fetch;
    this.#pusher = options.pusher ?? new GitHubHttpsCommitPusher();
    this.#now = options.now ?? (() => new Date());
  }

  async publish(input: {
    task: TaskSpec;
    artifact: GitIntegrationArtifact;
    workspace: string;
  }): Promise<PublishedPullRequest> {
    const { task, artifact } = input;
    if (
      artifact.task_id !== task.task_id ||
      artifact.repo_id !== task.repo_id ||
      artifact.base_sha !== task.base_sha
    ) {
      throw new ControllerError(
        "GITHUB_PUBLISH_BINDING_MISMATCH",
        "Integration artifact is not bound to publication task",
      );
    }

    const credential = await this.#credentials.issueForRepo(task.repo_id);
    if (!credential.token) {
      throw new ControllerError(
        "GITHUB_TOKEN_INVALID",
        "GitHub App credential broker returned an empty installation token",
      );
    }
    const expiresAt = Date.parse(credential.expires_at);
    if (
      !Number.isFinite(expiresAt) ||
      expiresAt <= this.#now().getTime() + 60_000
    ) {
      throw new ControllerError(
        "GITHUB_TOKEN_EXPIRED",
        "GitHub App installation token is expired or too close to expiry",
      );
    }

    const api = new GitHubRestApi(credential.token, this.#fetch);
    const currentBase = await api.getBranchHead(task.repo_id, task.base_ref);
    if (currentBase !== task.base_sha) {
      throw new ControllerError(
        "BASE_DRIFT",
        "GitHub base branch changed before PR publication",
        { expected: task.base_sha, observed: currentBase },
      );
    }

    const branch = integrationBranchName(artifact);
    const existingBranch = await api.getBranchHead(task.repo_id, branch);
    if (
      existingBranch !== null &&
      existingBranch !== artifact.commit_sha
    ) {
      throw new ControllerError(
        "GITHUB_BRANCH_CONFLICT",
        "Deterministic integration branch exists at a different SHA",
        {
          branch,
          expected: artifact.commit_sha,
          observed: existingBranch,
        },
      );
    }

    if (existingBranch === null) {
      await this.#pusher.push({
        repoId: task.repo_id,
        branch,
        commitSha: artifact.commit_sha,
        workspace: input.workspace,
        token: credential.token,
      });
    }

    const pushedHead = await api.getBranchHead(task.repo_id, branch);
    if (pushedHead !== artifact.commit_sha) {
      throw new ControllerError(
        "GITHUB_PUSH_VERIFICATION_FAILED",
        "Remote branch head does not equal deterministic integration commit",
        {
          branch,
          expected: artifact.commit_sha,
          observed: pushedHead,
        },
      );
    }

    const existingPulls = await api.listOpenPulls(
      task.repo_id,
      branch,
      task.base_ref,
    );
    if (existingPulls.length > 1) {
      throw new ControllerError(
        "GITHUB_PR_CONFLICT",
        "Multiple open pull requests match the deterministic integration branch",
      );
    }

    let pull = existingPulls[0];
    if (!pull) {
      pull = await api.createPull({
        repoId: task.repo_id,
        branch,
        baseRef: task.base_ref,
        title: "AWF: " + task.objective.slice(0, 180),
        body:
          "Autonomous Worker Fleet candidate.\n\n" +
          "Candidate: " +
          artifact.candidate_hash +
          "\n" +
          "Integration commit: " +
          artifact.commit_sha +
          "\n",
      });
    }

    const observed = await api.getPull(task.repo_id, pull.number);
    if (
      observed.state !== "open" ||
      observed.head.ref !== branch ||
      observed.head.sha.toLowerCase() !== artifact.commit_sha ||
      observed.base.ref !== task.base_ref ||
      observed.base.sha.toLowerCase() !== task.base_sha
    ) {
      throw new ControllerError(
        "GITHUB_PR_BINDING_MISMATCH",
        "Published pull request is not exact-SHA/base bound",
        {
          pullNumber: pull.number,
          headRef: observed.head.ref,
          headSha: observed.head.sha,
          baseRef: observed.base.ref,
          baseSha: observed.base.sha,
        },
      );
    }

    return {
      schema_version: "1.0",
      provider: "github",
      repo_id: task.repo_id,
      task_id: task.task_id,
      attempt_id: artifact.attempt_id,
      integration_artifact_hash: artifact.artifact_hash,
      branch,
      pr_number: observed.number,
      pr_url: observed.html_url,
      base_ref: observed.base.ref,
      base_sha: observed.base.sha.toLowerCase(),
      head_sha: observed.head.sha.toLowerCase(),
    };
  }
}

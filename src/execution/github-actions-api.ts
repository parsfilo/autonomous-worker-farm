import { trustedGitHubFetch } from "../net/trusted-github-fetch.js";
import { createHash } from "node:crypto";
import type { GitHubInstallationTokenProvider } from "../repo/github-write.js";
import { GITHUB_API_VERSION } from "../repo/github-write.js";
import { ControllerError } from "../lib/errors.js";

const API_BASE = "https://api.github.com";

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

export interface GitHubActionsDispatchResult {
  workflow_run_id: number;
  run_url: string;
  html_url: string;
}

export interface GitHubActionsRunObservation {
  id: number;
  status: string;
  conclusion: string | null;
  run_attempt: number;
  html_url: string;
  created_at: string;
  run_started_at: string | null;
  updated_at: string;
  head_sha: string;
  event: string;
  path: string;
}

export interface GitHubActionsArtifactObservation {
  id: number;
  name: string;
  size_in_bytes: number;
  expired: boolean;
  digest: string;
  archive_download_url: string;
}

export class GitHubActionsApi {
  readonly #credentials: GitHubInstallationTokenProvider;
  readonly #fetch: typeof fetch;

  constructor(
    credentials: GitHubInstallationTokenProvider,
    fetchImpl: typeof fetch = trustedGitHubFetch,
  ) {
    this.#credentials = credentials;
    this.#fetch = fetchImpl;
  }

  async #token(repoId: string): Promise<string> {
    const credential = await this.#credentials.issueForRepo(repoId);
    if (!credential.token) {
      throw new ControllerError(
        "GITHUB_TOKEN_INVALID",
        "GitHub App installation token is empty",
      );
    }
    if (Date.parse(credential.expires_at) <= Date.now() + 60_000) {
      throw new ControllerError(
        "GITHUB_TOKEN_EXPIRED",
        "GitHub App installation token is expired or too close to expiry",
      );
    }
    return credential.token;
  }

  async #request(
    repoId: string,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<Response> {
    const token = await this.#token(repoId);
    const response = await this.#fetch(API_BASE + path, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: "Bearer " + token,
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "autonomous-worker-controller/0.1",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      redirect: "follow",
    });
    if (!response.ok) {
      throw new ControllerError(
        "GITHUB_ACTIONS_API_FAILED",
        "GitHub Actions REST request failed",
        {
          method,
          path,
          status: response.status,
          response: (await response.text()).slice(0, 4096),
        },
      );
    }
    return response;
  }

  async getBranchHead(workerRepo: string, branch: string): Promise<string> {
    if (
      !/^[A-Za-z0-9._\/-]{1,255}$/.test(branch) ||
      branch.startsWith("/") ||
      branch.endsWith("/") ||
      branch.includes("..") ||
      branch.includes("//")
    ) {
      throw new ControllerError(
        "GITHUB_ACTIONS_REF_INVALID",
        "GitHub Actions dispatch ref must be a safe branch name",
      );
    }
    const { owner, repo } = parseRepoId(workerRepo);
    const encoded = branch.split("/").map(encodeURIComponent).join("/");
    const response = await this.#request(
      workerRepo,
      "GET",
      "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/git/ref/heads/" +
        encoded,
    );
    const value = (await response.json()) as { object?: { type?: string; sha?: string } };
    const sha = value.object?.sha?.toLowerCase() ?? "";
    if (value.object?.type !== "commit" || !/^[0-9a-f]{40}$/.test(sha)) {
      throw new ControllerError(
        "GITHUB_ACTIONS_REF_INVALID",
        "Worker-farm branch did not resolve to a canonical commit SHA",
      );
    }
    return sha;
  }

  async dispatch(input: {
    workerRepo: string;
    workflow: string;
    ref: string;
    inputs: Record<string, string>;
  }): Promise<GitHubActionsDispatchResult> {
    const { owner, repo } = parseRepoId(input.workerRepo);
    const response = await this.#request(
      input.workerRepo,
      "POST",
      "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/actions/workflows/" +
        encodeURIComponent(input.workflow) +
        "/dispatches",
      { ref: input.ref, inputs: input.inputs },
    );
    if (response.status !== 200) {
      throw new ControllerError(
        "GITHUB_ACTIONS_DISPATCH_RESPONSE_INVALID",
        "Workflow dispatch did not return the current GitHub run-id response",
        { status: response.status },
      );
    }
    const value = (await response.json()) as Partial<GitHubActionsDispatchResult>;
    if (
      !Number.isInteger(value.workflow_run_id) ||
      Number(value.workflow_run_id) < 1 ||
      typeof value.run_url !== "string" ||
      typeof value.html_url !== "string"
    ) {
      throw new ControllerError(
        "GITHUB_ACTIONS_DISPATCH_RESPONSE_INVALID",
        "Workflow dispatch response did not contain a usable run id/url",
      );
    }
    return value as GitHubActionsDispatchResult;
  }

  async getRun(workerRepo: string, runId: number): Promise<GitHubActionsRunObservation> {
    const { owner, repo } = parseRepoId(workerRepo);
    const response = await this.#request(
      workerRepo,
      "GET",
      "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/actions/runs/" +
        String(runId),
    );
    const value = (await response.json()) as GitHubActionsRunObservation;
    if (value.id !== runId || !value.status || !value.html_url || !value.path) {
      throw new ControllerError(
        "GITHUB_ACTIONS_RUN_INVALID",
        "GitHub Actions run payload is invalid or mismatched",
      );
    }
    return value;
  }

  async cancelRun(workerRepo: string, runId: number): Promise<void> {
    const { owner, repo } = parseRepoId(workerRepo);
    await this.#request(
      workerRepo,
      "POST",
      "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/actions/runs/" +
        String(runId) +
        "/cancel",
    );
  }

  async listRunArtifacts(
    workerRepo: string,
    runId: number,
    name: string,
  ): Promise<GitHubActionsArtifactObservation[]> {
    const { owner, repo } = parseRepoId(workerRepo);
    const query = new URLSearchParams({ name, per_page: "100" });
    const response = await this.#request(
      workerRepo,
      "GET",
      "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/actions/runs/" +
        String(runId) +
        "/artifacts?" +
        query.toString(),
    );
    const value = (await response.json()) as {
      artifacts?: GitHubActionsArtifactObservation[];
    };
    return (value.artifacts ?? []).filter(
      (artifact) =>
        artifact.name === name &&
        Number.isInteger(artifact.id) &&
        artifact.id > 0 &&
        !artifact.expired &&
        /^sha256:[0-9a-f]{64}$/.test(artifact.digest),
    );
  }

  async downloadArtifact(
    workerRepo: string,
    artifact: GitHubActionsArtifactObservation,
  ): Promise<Uint8Array> {
    const { owner, repo } = parseRepoId(workerRepo);
    const response = await this.#request(
      workerRepo,
      "GET",
      "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/actions/artifacts/" +
        String(artifact.id) +
        "/zip",
    );
    const bytes = new Uint8Array(await response.arrayBuffer());
    const actual = "sha256:" + createHash("sha256").update(bytes).digest("hex");
    if (actual !== artifact.digest) {
      throw new ControllerError(
        "GITHUB_ACTIONS_ARTIFACT_DIGEST_MISMATCH",
        "Downloaded GitHub Actions artifact digest does not match GitHub metadata",
        { expected: artifact.digest, actual },
      );
    }
    return bytes;
  }

  async deleteArtifact(workerRepo: string, artifactId: number): Promise<void> {
    const { owner, repo } = parseRepoId(workerRepo);
    await this.#request(
      workerRepo,
      "DELETE",
      "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/actions/artifacts/" +
        String(artifactId),
    );
  }

}

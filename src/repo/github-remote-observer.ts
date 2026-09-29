import type {
  GitIntegrationArtifact,
  RemoteVerificationReport,
  TaskSpec,
} from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";
import {
  GitHubRestApi,
  type GitHubInstallationTokenProvider,
  type GitHubCheckRunObservation,
  type GitHubCombinedStatusObservation,
  type PublishedPullRequest,
} from "./github-write.js";
import { finalizeRemoteVerificationReport } from "./remote-verification.js";

export interface GitHubRemoteObserverOptions {
  credentials: GitHubInstallationTokenProvider;
  fetch?: typeof fetch;
  now?: () => Date;
  build?: string;
}

function mapCheckRun(
  run: GitHubCheckRunObservation,
): RemoteVerificationReport["remote_checks"][number]["status"] {
  if (run.status !== "completed") return "PENDING";
  switch (run.conclusion) {
    case "success":
    case "neutral":
    case "skipped":
      return "PASS";
    case "failure":
    case "cancelled":
    case "timed_out":
    case "action_required":
    case "startup_failure":
    case "stale":
      return "FAIL";
    case null:
      return "PENDING";
    default:
      return "ERROR";
  }
}

function mapCommitStatus(
  state: string,
): RemoteVerificationReport["remote_checks"][number]["status"] {
  switch (state) {
    case "success":
      return "PASS";
    case "pending":
      return "PENDING";
    case "failure":
      return "FAIL";
    case "error":
      return "ERROR";
    default:
      return "ERROR";
  }
}

function mapPullState(pull: {
  state: string;
  merged?: boolean;
}): RemoteVerificationReport["pr_state"] {
  if (pull.merged === true) return "MERGED";
  return pull.state === "open" ? "OPEN" : "CLOSED";
}

function statusForObservation(input: {
  baseMatches: boolean;
  prState: RemoteVerificationReport["pr_state"];
  baseRefMatches: boolean;
  headMatches: boolean;
  checks: RemoteVerificationReport["remote_checks"];
}): RemoteVerificationReport["status"] {
  if (!input.baseMatches) return "BASE_DRIFT";
  if (!input.headMatches) return "HEAD_MISMATCH";
  if (input.prState !== "OPEN" || !input.baseRefMatches) {
    return "EXTERNAL_BLOCKER";
  }
  if (
    input.checks.some(
      (check) => check.status === "FAIL" || check.status === "ERROR",
    )
  ) {
    return "QUALITY_FAILED";
  }
  if (input.checks.some((check) => check.status === "PENDING")) {
    return "PENDING";
  }
  return "PASS";
}

function ensurePublicationBinding(input: {
  task: TaskSpec;
  artifact: GitIntegrationArtifact;
  publication: PublishedPullRequest;
}): void {
  const { task, artifact, publication } = input;
  if (
    artifact.task_id !== task.task_id ||
    artifact.repo_id !== task.repo_id ||
    artifact.base_sha !== task.base_sha ||
    publication.task_id !== task.task_id ||
    publication.attempt_id !== artifact.attempt_id ||
    publication.repo_id !== task.repo_id ||
    publication.integration_artifact_hash !== artifact.artifact_hash ||
    publication.base_ref !== task.base_ref ||
    publication.base_sha !== task.base_sha ||
    publication.head_sha !== artifact.commit_sha
  ) {
    throw new ControllerError(
      "REMOTE_OBSERVER_BINDING_MISMATCH",
      "GitHub publication is not bound to the deterministic integration artifact",
    );
  }
}

export class GitHubRemoteObserver {
  readonly #credentials: GitHubInstallationTokenProvider;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;
  readonly #build: string;

  constructor(options: GitHubRemoteObserverOptions) {
    this.#credentials = options.credentials;
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? (() => new Date());
    this.#build = options.build ?? "github-remote-observer-v1";
  }

  async observe(input: {
    task: TaskSpec;
    artifact: GitIntegrationArtifact;
    publication: PublishedPullRequest;
  }): Promise<RemoteVerificationReport> {
    ensurePublicationBinding(input);
    const { task, artifact, publication } = input;

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
    const observedBase = await api.getBranchHead(task.repo_id, task.base_ref);
    if (observedBase === null) {
      throw new ControllerError(
        "GITHUB_BASE_REF_MISSING",
        "GitHub base branch disappeared during remote verification",
      );
    }

    const pull = await api.getPull(task.repo_id, publication.pr_number);
    const prState = mapPullState(pull);
    const observedHead = pull.head.sha.toLowerCase();
    const observedPullBase = pull.base.sha.toLowerCase();
    const baseMatches =
      observedBase === task.base_sha &&
      observedPullBase === task.base_sha;
    const baseRefMatches = pull.base.ref === task.base_ref;
    const headMatches =
      pull.head.ref === publication.branch &&
      observedHead === artifact.commit_sha;

    const remoteChecks: RemoteVerificationReport["remote_checks"] = [];
    if (
      baseMatches &&
      baseRefMatches &&
      headMatches &&
      prState === "OPEN"
    ) {
      const checkRuns = await api.listCheckRuns(
        task.repo_id,
        artifact.commit_sha,
      );
      for (const run of checkRuns) {
        remoteChecks.push({
          name: "check:" + String(run.id) + ":" + run.name,
          status: mapCheckRun(run),
          head_sha: run.head_sha,
        });
      }

      const combined: GitHubCombinedStatusObservation =
        await api.getCombinedStatus(task.repo_id, artifact.commit_sha);
      if (combined.sha !== artifact.commit_sha) {
        throw new ControllerError(
          "GITHUB_COMMIT_STATUS_SHA_MISMATCH",
          "GitHub combined status is not bound to deterministic integration commit",
          {
            expected: artifact.commit_sha,
            observed: combined.sha,
          },
        );
      }
      for (const status of combined.statuses) {
        remoteChecks.push({
          name: "status:" + status.context,
          status: mapCommitStatus(status.state),
          head_sha: artifact.commit_sha,
        });
      }
    }

    const status = statusForObservation({
      baseMatches,
      prState,
      baseRefMatches,
      headMatches,
      checks: remoteChecks,
    });

    return finalizeRemoteVerificationReport({
      schema_version: "1.0",
      provider: "github",
      task_id: task.task_id,
      attempt_id: artifact.attempt_id,
      repo_id: task.repo_id,
      candidate_hash: artifact.candidate_hash,
      integration_artifact_hash: artifact.artifact_hash,
      expected_base_sha: task.base_sha,
      expected_commit_sha: artifact.commit_sha,
      base_ref: task.base_ref,
      observed_base_sha: observedBase,
      pr_number: publication.pr_number,
      pr_state: prState,
      pr_head_ref: pull.head.ref,
      observed_pr_head_sha: observedHead,
      status,
      remote_checks: remoteChecks,
      observed_at: this.#now().toISOString(),
      observer: {
        kind: "trusted-git-integrator",
        build: this.#build,
      },
    });
  }
}

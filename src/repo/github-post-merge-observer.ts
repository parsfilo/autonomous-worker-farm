import type {
  GitHubMergeReceipt,
  PostMergeVerificationReport,
  RepoPassport,
  TaskSpec,
} from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";
import {
  GitHubRestApi,
  type GitHubInstallationTokenProvider,
} from "./github-write.js";
import { finalizePostMergeVerificationReport } from "./post-merge-verification.js";

export interface GitHubPostMergeObserverOptions {
  credentials: GitHubInstallationTokenProvider;
  fetch?: typeof fetch;
  now?: () => Date;
  build?: string;
}

type CheckStatus = PostMergeVerificationReport["observed_checks"][number]["status"];

function checkRunStatus(status: string, conclusion: string | null): CheckStatus {
  if (status !== "completed") return "PENDING";
  switch (conclusion) {
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

function commitStatus(state: string): CheckStatus {
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

function aggregate(values: CheckStatus[]): CheckStatus {
  if (values.length === 0) return "PENDING";
  if (values.includes("ERROR")) return "ERROR";
  if (values.includes("FAIL")) return "FAIL";
  if (values.includes("PENDING")) return "PENDING";
  return "PASS";
}

export class GitHubPostMergeObserver {
  readonly #credentials: GitHubInstallationTokenProvider;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;
  readonly #build: string;

  constructor(options: GitHubPostMergeObserverOptions) {
    this.#credentials = options.credentials;
    this.#fetch = options.fetch ?? fetch;
    this.#now = options.now ?? (() => new Date());
    this.#build = options.build ?? "github-post-merge-observer-v1";
  }

  async observe(input: {
    task: TaskSpec;
    passport: RepoPassport;
    receipt: GitHubMergeReceipt;
  }): Promise<PostMergeVerificationReport> {
    const { task, passport, receipt } = input;
    if (
      receipt.task_id !== task.task_id ||
      receipt.repo_id !== task.repo_id ||
      receipt.merge_method !== passport.merge_method
    ) {
      throw new ControllerError(
        "POST_MERGE_OBSERVER_BINDING_MISMATCH",
        "Merge receipt is not bound to task/passport",
      );
    }

    const credential = await this.#credentials.issueForRepo(task.repo_id);
    const expiresAt = Date.parse(credential.expires_at);
    if (
      !credential.token ||
      !Number.isFinite(expiresAt) ||
      expiresAt <= this.#now().getTime() + 60_000
    ) {
      throw new ControllerError(
        "GITHUB_TOKEN_EXPIRED",
        "GitHub App installation token is missing, expired, or too close to expiry",
      );
    }
    const api = new GitHubRestApi(credential.token, this.#fetch);
    const currentBase = await api.getBranchHead(task.repo_id, task.base_ref);
    if (currentBase === null) {
      throw new ControllerError(
        "GITHUB_BASE_REF_MISSING",
        "Default branch disappeared during post-merge verification",
      );
    }

    let observedChecks: PostMergeVerificationReport["observed_checks"] = [];
    let status: PostMergeVerificationReport["status"];

    if (
      receipt.base_head_matches_merge === false ||
      currentBase !== receipt.merge_sha
    ) {
      status = "EXTERNAL_BLOCKER";
    } else {
      const runs = await api.listCheckRuns(task.repo_id, receipt.merge_sha);
      const combined = await api.getCombinedStatus(
        task.repo_id,
        receipt.merge_sha,
      );
      if (combined.sha !== receipt.merge_sha) {
        throw new ControllerError(
          "POST_MERGE_STATUS_SHA_MISMATCH",
          "Combined status is not bound to exact merge SHA",
        );
      }

      observedChecks = passport.post_merge_checks.map((name) => {
        const statuses: CheckStatus[] = [];
        for (const run of runs) {
          if (run.head_sha !== receipt.merge_sha) {
            throw new ControllerError(
              "POST_MERGE_CHECK_SHA_MISMATCH",
              "GitHub check run is not bound to exact merge SHA",
              { name: run.name, headSha: run.head_sha },
            );
          }
          if (run.name === name) {
            statuses.push(checkRunStatus(run.status, run.conclusion));
          }
        }
        for (const legacy of combined.statuses) {
          if (legacy.context === name) {
            statuses.push(commitStatus(legacy.state));
          }
        }
        return {
          name,
          status: aggregate(statuses),
          head_sha: receipt.merge_sha,
        };
      });

      if (
        observedChecks.some(
          (check) => check.status === "FAIL" || check.status === "ERROR",
        )
      ) {
        status = "QUALITY_FAILED";
      } else if (observedChecks.some((check) => check.status === "PENDING")) {
        status = "PENDING";
      } else {
        status = "PASS";
      }
    }

    return finalizePostMergeVerificationReport({
      schema_version: "1.0",
      provider: "github",
      task_id: task.task_id,
      attempt_id: receipt.attempt_id,
      repo_id: task.repo_id,
      merge_receipt_hash: receipt.receipt_hash,
      merge_sha: receipt.merge_sha,
      required_checks: [...passport.post_merge_checks].sort(),
      observed_checks: observedChecks,
      status,
      observed_at: this.#now().toISOString(),
      observer: {
        kind: "trusted-git-integrator",
        build: this.#build,
      },
    });
  }
}

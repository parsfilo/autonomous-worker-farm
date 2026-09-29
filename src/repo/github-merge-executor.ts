import { trustedGitHubFetch } from "../net/trusted-github-fetch.js";
import { ControllerCore } from "../controller/controller.js";
import { ControllerError } from "../lib/errors.js";
import {
  GitHubRestApi,
  type GitHubInstallationTokenProvider,
} from "./github-write.js";
import { GitHubRemoteObserver } from "./github-remote-observer.js";
import { finalizeGitHubMergeReceipt } from "./github-merge-receipt.js";

export interface GitHubMergeExecutorOptions {
  core: ControllerCore;
  credentials: GitHubInstallationTokenProvider;
  fetch?: typeof fetch;
  now?: () => Date;
  build?: string;
}

export class GitHubMergeExecutor {
  readonly #core: ControllerCore;
  readonly #credentials: GitHubInstallationTokenProvider;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;
  readonly #build: string;

  constructor(options: GitHubMergeExecutorOptions) {
    this.#core = options.core;
    this.#credentials = options.credentials;
    this.#fetch = options.fetch ?? trustedGitHubFetch;
    this.#now = options.now ?? (() => new Date());
    this.#build = options.build ?? "github-merge-executor-v1";
  }

  async #api(repoId: string): Promise<GitHubRestApi> {
    const credential = await this.#credentials.issueForRepo(repoId);
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
    return new GitHubRestApi(credential.token, this.#fetch);
  }

  async execute(input: {
    taskId: string;
    correlationId: string;
    actorId: string;
  }) {
    const taskRecord = this.#core.getTask(input.taskId);
    if (taskRecord.state !== "READY_TO_MERGE") {
      throw new ControllerError(
        "MERGE_GATE_NOT_READY",
        "Trusted merge requires READY_TO_MERGE task state",
        { state: taskRecord.state },
      );
    }
    const attempt = this.#core.getPrIntegrationCandidate(input.taskId);
    const integration = attempt.integration_candidate;
    const publication = attempt.pull_request;
    const persistedRemote = attempt.remote_verification_report;
    if (
      !integration ||
      !publication ||
      persistedRemote?.status !== "PASS"
    ) {
      throw new ControllerError(
        "MERGE_EVIDENCE_NOT_READY",
        "Trusted merge requires deterministic integration, PR publication, and persisted remote PASS",
      );
    }

    const preMergeObserver = new GitHubRemoteObserver({
      credentials: this.#credentials,
      fetch: this.#fetch,
      now: this.#now,
      build: this.#build + ":premerge",
    });
    const freshRemote = await preMergeObserver.observe({
      task: taskRecord.spec,
      artifact: integration,
      publication,
    });
    if (freshRemote.status !== "PASS") {
      throw new ControllerError(
        "MERGE_REMOTE_RECHECK_FAILED",
        "GitHub remote evidence changed after READY_TO_MERGE; refusing merge",
        {
          status: freshRemote.status,
          observedBaseSha: freshRemote.observed_base_sha,
          observedHeadSha: freshRemote.observed_pr_head_sha,
        },
      );
    }

    const passport = this.#core.getPassport(taskRecord.spec.repo_id).passport;
    this.#core.requestMerge(
      input.taskId,
      input.correlationId,
      input.actorId,
    );
    const api = await this.#api(taskRecord.spec.repo_id);

    try {
      const merged = await api.mergePull(
        taskRecord.spec.repo_id,
        publication.pr_number,
        integration.commit_sha,
        passport.merge_method,
      );
      let observedBase: string | null = null;
      try {
        observedBase = await api.getBranchHead(
          taskRecord.spec.repo_id,
          taskRecord.spec.base_ref,
        );
      } catch {
        observedBase = null;
      }
      const receipt = finalizeGitHubMergeReceipt({
        schema_version: "1.0",
        provider: "github",
        repo_id: taskRecord.spec.repo_id,
        task_id: taskRecord.spec.task_id,
        attempt_id: attempt.attempt_id,
        pr_number: publication.pr_number,
        integration_artifact_hash: integration.artifact_hash,
        remote_verification_report_hash: persistedRemote.report_hash,
        expected_head_sha: integration.commit_sha,
        merge_method: passport.merge_method,
        merge_sha: merged.sha,
        observed_base_sha: observedBase,
        base_head_matches_merge:
          observedBase === null ? null : observedBase === merged.sha,
        merged_at: this.#now().toISOString(),
        observer: {
          kind: "trusted-git-integrator",
          build: this.#build,
        },
      });
      const task = this.#core.completeMerge(receipt);
      return { task, receipt };
    } catch (error) {
      try {
        const pull = await api.getPull(
          taskRecord.spec.repo_id,
          publication.pr_number,
        );
        const recoveredMergeSha = pull.merge_commit_sha?.toLowerCase() ?? null;
        if (
          pull.merged === true &&
          recoveredMergeSha &&
          /^[0-9a-f]{40}$/.test(recoveredMergeSha)
        ) {
          let observedBase: string | null = null;
          try {
            observedBase = await api.getBranchHead(
              taskRecord.spec.repo_id,
              taskRecord.spec.base_ref,
            );
          } catch {
            observedBase = null;
          }
          const receipt = finalizeGitHubMergeReceipt({
            schema_version: "1.0",
            provider: "github",
            repo_id: taskRecord.spec.repo_id,
            task_id: taskRecord.spec.task_id,
            attempt_id: attempt.attempt_id,
            pr_number: publication.pr_number,
            integration_artifact_hash: integration.artifact_hash,
            remote_verification_report_hash: persistedRemote.report_hash,
            expected_head_sha: integration.commit_sha,
            merge_method: passport.merge_method,
            merge_sha: recoveredMergeSha,
            observed_base_sha: observedBase,
            base_head_matches_merge:
              observedBase === null
                ? null
                : observedBase === recoveredMergeSha,
            merged_at: this.#now().toISOString(),
            observer: {
              kind: "trusted-git-integrator",
              build: this.#build + ":reconciled",
            },
          });
          const task = this.#core.completeMerge(receipt);
          return { task, receipt };
        }
      } catch {
        // Fall through to an explicit Controller blocker below.
      }

      const value = error as { code?: string; message?: string };
      this.#core.failMergeExternal(
        input.taskId,
        "MERGE_REMOTE_OPERATION_FAILED",
        {
          code: value.code ?? "UNKNOWN",
          message: value.message ?? String(error),
          pr_number: publication.pr_number,
          expected_head_sha: integration.commit_sha,
        },
      );
      throw error;
    }
  }
}

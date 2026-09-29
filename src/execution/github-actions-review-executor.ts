import { trustedGitHubFetch } from "../net/trusted-github-fetch.js";
import type { IndependentReviewReport, QualityProfile } from "../../contracts/types.js";
import { ControllerCore } from "../controller/controller.js";
import { ControllerError } from "../lib/errors.js";
import { loadTrustedQualityProfile } from "../quality/profile.js";
import type { GitHubInstallationTokenProvider } from "../repo/github-write.js";
import { buildIndependentReviewTask } from "./independent-review-executor.js";
import { GitHubActionsApi } from "./github-actions-api.js";
import { parseGitHubActionsReviewArtifact } from "./github-actions-review-artifact.js";
import { githubActionsReviewRequestHash } from "./github-actions-review-binding.js";
import { finalizeGitHubActionsExecutionReceipt } from "./github-actions-receipt.js";
import { verifyGitHubActionsOidc } from "./github-oidc.js";

const DEFAULT_POLL_MS = 2500;

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function parseJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new ControllerError(
      "GITHUB_ACTIONS_REVIEW_ARTIFACT_INVALID",
      label + " is not valid JSON",
    );
  }
}

export interface GitHubActionsReviewExecutorOptions {
  core: ControllerCore;
  credentials: GitHubInstallationTokenProvider;
  workerRepo: string;
  workflow: string;
  dispatchRef: string;
  workflowSha: string;
  qualityProfileRoot: string;
  pollIntervalMs?: number;
  fetch?: typeof fetch;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  api?: GitHubActionsApi;
}

export class GitHubActionsReviewExecutor {
  readonly #core: ControllerCore;
  readonly #workerRepo: string;
  readonly #workflow: string;
  readonly #dispatchRef: string;
  readonly #workflowSha: string;
  readonly #qualityProfileRoot: string;
  readonly #pollIntervalMs: number;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #api: GitHubActionsApi;

  constructor(options: GitHubActionsReviewExecutorOptions) {
    this.#core = options.core;
    this.#workerRepo = options.workerRepo;
    this.#workflow = options.workflow;
    this.#dispatchRef = options.dispatchRef;
    this.#workflowSha = options.workflowSha.toLowerCase();
    this.#qualityProfileRoot = options.qualityProfileRoot;
    this.#pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_MS;
    this.#fetch = options.fetch ?? trustedGitHubFetch;
    this.#now = options.now ?? (() => new Date());
    this.#sleep =
      options.sleep ??
      (async (ms) => {
        await new Promise((resolve) => setTimeout(resolve, ms));
      });
    this.#api = options.api ?? new GitHubActionsApi(options.credentials, this.#fetch);
    if (
      !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(this.#workerRepo) ||
      !this.#workflow ||
      !this.#dispatchRef ||
      !/^[0-9a-f]{40}$/.test(this.#workflowSha)
    ) {
      throw new ControllerError(
        "GITHUB_ACTIONS_EXECUTOR_CONFIG_INVALID",
        "Review executor worker repo/workflow/ref/SHA configuration is invalid",
      );
    }
  }

  async execute(reviewId: string): Promise<{
    review: ReturnType<ControllerCore["getReview"]>;
    report: IndependentReviewReport;
    workflowRunId: number;
  }> {
    const review = this.#core.getReview(reviewId);
    const taskRecord = this.#core.getTask(review.task_id);
    const task = taskRecord.spec;
    const sourceAttempt = this.#core.getAttempt(review.source_attempt_id);
    const { passport } = this.#core.getPassport(task.repo_id);
    const profile: QualityProfile = loadTrustedQualityProfile(
      this.#qualityProfileRoot,
      task.quality_profile,
    );
    if (
      review.execution_backend !== "github-actions" ||
      !["LEASED", "PROVISIONING", "RUNNING"].includes(review.state) ||
      !review.machine_id ||
      !review.model
    ) {
      throw new ControllerError(
        "REVIEW_STATE_INVALID",
        "GitHub Actions review executor requires a github-actions LEASED/PROVISIONING/RUNNING review",
        { reviewState: review.state },
      );
    }
    const sourceExecution = sourceAttempt.github_actions_execution;
    if (
      sourceAttempt.execution_backend !== "github-actions" ||
      !sourceExecution ||
      !sourceAttempt.result_manifest ||
      sourceAttempt.result_manifest.candidate_hash !== review.candidate_hash ||
      sourceAttempt.result_manifest.patch_sha256 !== review.patch_sha256 ||
      sourceExecution.worker_repo !== this.#workerRepo
    ) {
      throw new ControllerError(
        "REVIEW_SOURCE_EVIDENCE_MISSING",
        "GitHub Actions reviewer requires the exact retained source write artifact/evidence",
      );
    }

    const reviewSpec = buildIndependentReviewTask(task, sourceAttempt.attempt_id);
    const requestHash = githubActionsReviewRequestHash({
      reviewId,
      taskId: task.task_id,
      sourceAttemptId: sourceAttempt.attempt_id,
      candidateHash: review.candidate_hash,
      patchSha256: review.patch_sha256,
      machineId: review.machine_id,
      model: review.model.model,
      workerRepo: this.#workerRepo,
      workflow: this.#workflow,
      workflowSha: this.#workflowSha,
      sourceArtifactId: sourceExecution.artifact_id,
      sourceArtifactDigest: sourceExecution.artifact_digest,
    });
    const artifactName = "awf-review-" + reviewId;
    let dispatch:
      | {
          workflow_run_id: number;
          run_url: string;
        }
      | undefined;

    if (review.state === "LEASED") {
      const observedWorkflowSha = await this.#api.getBranchHead(
        this.#workerRepo,
        this.#dispatchRef,
      );
      if (observedWorkflowSha !== this.#workflowSha) {
        throw new ControllerError(
          "GITHUB_ACTIONS_WORKFLOW_SHA_MISMATCH",
          "Worker-farm review branch does not match the Controller-pinned workflow commit",
          { expected: this.#workflowSha, observed: observedWorkflowSha },
        );
      }

      const parts = task.repo_id.split("/");
      const created = await this.#api.dispatch({
        workerRepo: this.#workerRepo,
        workflow: this.#workflow,
        ref: this.#dispatchRef,
        inputs: {
          mode: "review",
          attempt_id: reviewId,
          attempt_no: "1",
          machine_id: review.machine_id,
          model: review.model.model,
          artifact_name: artifactName,
          target_repo: task.repo_id,
          target_owner: parts[0]!,
          target_name: parts[1]!,
          target_visibility: passport.visibility,
          base_sha: task.base_sha,
          task_b64: encodeJson(reviewSpec),
          passport_b64: encodeJson(passport),
          quality_profile_b64: encodeJson(profile),
          source_attempt_id: sourceAttempt.attempt_id,
          source_artifact_id: String(sourceExecution.artifact_id),
          source_artifact_digest: sourceExecution.artifact_digest,
          candidate_hash: review.candidate_hash,
          patch_sha256: review.patch_sha256,
        },
      });
      this.#core.beginGitHubActionsReviewProvisioning(
        reviewId,
        {
          worker_repo: this.#workerRepo,
          workflow: this.#workflow,
          dispatch_ref: this.#dispatchRef,
          workflow_run_id: created.workflow_run_id,
          run_url: created.run_url,
          workflow_sha: this.#workflowSha,
        },
        requestHash,
      );
      dispatch = created;
    } else {
      const stored = review.github_actions_dispatch;
      if (
        !stored ||
        stored.worker_repo !== this.#workerRepo ||
        stored.workflow !== this.#workflow ||
        stored.dispatch_ref !== this.#dispatchRef ||
        stored.workflow_sha !== this.#workflowSha
      ) {
        throw new ControllerError(
          "GITHUB_ACTIONS_REVIEW_RESUME_BINDING_MISMATCH",
          "Stored GitHub Actions review dispatch does not match the configured trusted worker binding",
        );
      }
      if (review.sandbox_request_hash !== requestHash) {
        throw new ControllerError(
          "GITHUB_ACTIONS_REVIEW_RESUME_BINDING_MISMATCH",
          "Stored GitHub Actions review request hash changed before resume",
        );
      }
      dispatch = {
        workflow_run_id: stored.workflow_run_id,
        run_url: stored.run_url,
      };
    }

    const deadline =
      this.#now().getTime() +
      Math.max(task.lease_ttl_seconds, task.timeout_seconds + 300) * 1000;
    let markedRunning = review.state === "RUNNING";
    let run = await this.#api.getRun(this.#workerRepo, dispatch.workflow_run_id);
    for (;;) {
      if (run.head_sha.toLowerCase() !== this.#workflowSha) {
        try {
          await this.#api.cancelRun(this.#workerRepo, run.id);
        } catch {}
        this.#core.failReview(reviewId, "GITHUB_ACTIONS_WORKFLOW_SHA_MISMATCH");
        throw new ControllerError(
          "GITHUB_ACTIONS_WORKFLOW_SHA_MISMATCH",
          "Review run is not executing the Controller-pinned worker-farm commit",
        );
      }
      if (!markedRunning && run.status !== "queued" && run.status !== "requested") {
        this.#core.markGitHubActionsReviewRunning(
          reviewId,
          run.run_started_at ?? run.created_at,
        );
        markedRunning = true;
      }
      if (run.status === "completed") break;
      if (this.#now().getTime() >= deadline) {
        try {
          await this.#api.cancelRun(this.#workerRepo, run.id);
        } catch {}
        this.#core.failReview(reviewId, "GITHUB_ACTIONS_REVIEW_TIMEOUT");
        throw new ControllerError(
          "GITHUB_ACTIONS_REVIEW_TIMEOUT",
          "GitHub Actions independent review exceeded its execution deadline",
        );
      }
      await this.#sleep(this.#pollIntervalMs);
      run = await this.#api.getRun(this.#workerRepo, dispatch.workflow_run_id);
    }
    if (!markedRunning) {
      this.#core.markGitHubActionsReviewRunning(
        reviewId,
        run.run_started_at ?? run.created_at,
      );
    }
    if (
      run.event !== "workflow_dispatch" ||
      run.path !== ".github/workflows/" + this.#workflow ||
      run.conclusion !== "success"
    ) {
      this.#core.failReview(reviewId, "GITHUB_ACTIONS_REVIEW_RUN_FAILED");
      throw new ControllerError(
        "GITHUB_ACTIONS_REVIEW_RUN_FAILED",
        "GitHub Actions review workflow did not complete successfully with expected identity",
      );
    }

    const artifacts = await this.#api.listRunArtifacts(
      this.#workerRepo,
      run.id,
      artifactName,
    );
    if (artifacts.length !== 1) {
      this.#core.failReview(reviewId, "GITHUB_ACTIONS_REVIEW_ARTIFACT_AMBIGUOUS");
      throw new ControllerError(
        "GITHUB_ACTIONS_REVIEW_ARTIFACT_AMBIGUOUS",
        "Expected exactly one non-expired review result artifact",
        { artifacts: artifacts.length },
      );
    }
    const artifact = artifacts[0]!;
    const zipBytes = await this.#api.downloadArtifact(this.#workerRepo, artifact);
    const parsed = await parseGitHubActionsReviewArtifact(zipBytes);
    const oidc = await verifyGitHubActionsOidc({
      jwt: parsed.oidcJwt,
      workerRepo: this.#workerRepo,
      workflow: this.#workflow,
      dispatchRef: this.#dispatchRef,
      workflowRunId: run.id,
      workflowRunAttempt: run.run_attempt,
      workflowSha: this.#workflowSha,
      fetch: this.#fetch,
      // OIDC is archival execution evidence. Verify its temporal validity at
      // the authenticated GitHub run completion timestamp, not at a later
      // Controller reconciliation wall clock.
      now: () => new Date(run.updated_at),
    });
    const receipt = finalizeGitHubActionsExecutionReceipt({
      schema_version: "1.0",
      backend: "github-actions",
      task_id: task.task_id,
      attempt_id: reviewId,
      machine_id: review.machine_id,
      worker_repo: this.#workerRepo,
      workflow: this.#workflow,
      dispatch_ref: this.#dispatchRef,
      workflow_run_id: run.id,
      run_attempt: run.run_attempt,
      run_url: dispatch.run_url,
      runner_environment: "github-hosted",
      status: "completed",
      conclusion: "success",
      started_at: run.run_started_at ?? run.created_at,
      completed_at: run.updated_at,
      artifact_id: artifact.id,
      artifact_name: artifact.name,
      artifact_digest: artifact.digest,
      workflow_sha: this.#workflowSha,
      oidc_sha256: oidc.oidcSha256,
    });
    this.#core.recordGitHubActionsReviewExecutionReceipt(reviewId, receipt);

    const report = parseJson<IndependentReviewReport>(
      parsed.reportJson,
      "independent-review-report.json",
    );
    const completed = this.#core.completeReview(reviewId, report);
    for (const artifactId of [artifact.id, sourceExecution.artifact_id]) {
      try {
        await this.#api.deleteArtifact(this.#workerRepo, artifactId);
      } catch {
        // One-day retention remains a bounded fallback cleanup path.
      }
    }
    return { review: completed, report, workflowRunId: run.id };
  }
}

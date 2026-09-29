import { trustedGitHubFetch } from "../net/trusted-github-fetch.js";
import { chmod, lstat, mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import type {
  QualityProfile,
  ResultManifest,
  VerificationReport,
} from "../../contracts/types.js";
import { ControllerCore } from "../controller/controller.js";
import {
  buildCandidateDescriptor,
  computeCandidateHash,
  sha256Bytes,
} from "../evidence/candidate.js";
import { verifyWorkerManifest } from "../evidence/verify-worker-manifest.js";
import { ControllerError } from "../lib/errors.js";
import {
  buildValidationPlanFromQualityProfile,
  loadTrustedQualityProfile,
} from "../quality/profile.js";
import type { GitHubInstallationTokenProvider } from "../repo/github-write.js";
import type { StoredAttempt } from "../store/file-store.js";
import { GitHubActionsApi } from "./github-actions-api.js";
import { parseGitHubActionsResultArtifact } from "./github-actions-artifact.js";
import { finalizeGitHubActionsExecutionReceipt } from "./github-actions-receipt.js";
import { verifyGitHubActionsOidc } from "./github-oidc.js";

const DEFAULT_POLL_MS = 2500;
const MAX_PATCH_BYTES = 32 * 1024 * 1024;

export interface GitHubActionsAttemptExecutorOptions {
  core: ControllerCore;
  credentials: GitHubInstallationTokenProvider;
  workerRepo: string;
  workflow: string;
  dispatchRef: string;
  workflowSha: string;
  candidateArtifactRoot: string;
  qualityProfileRoot: string;
  pollIntervalMs?: number;
  fetch?: typeof fetch;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  api?: GitHubActionsApi;
}

export interface GitHubActionsAttemptExecutionResult {
  attempt: StoredAttempt;
  manifest: ResultManifest;
  patchPath: string;
  verificationReport: VerificationReport;
  workflowRunId: number;
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

async function persistPatch(
  root: string,
  attemptId: string,
  patchBytes: Uint8Array,
): Promise<string> {
  if (!isAbsolute(root)) {
    throw new ControllerError(
      "CANDIDATE_ARTIFACT_ROOT_INVALID",
      "Candidate artifact root must be absolute",
    );
  }
  if (patchBytes.byteLength === 0 || patchBytes.byteLength > MAX_PATCH_BYTES) {
    throw new ControllerError(
      "CANDIDATE_PATCH_TOO_LARGE",
      "Candidate patch is empty or exceeds the Controller limit",
      { bytes: patchBytes.byteLength, maxBytes: MAX_PATCH_BYTES },
    );
  }
  await mkdir(root, { recursive: true, mode: 0o700 });
  const info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new ControllerError(
      "CANDIDATE_ARTIFACT_ROOT_INVALID",
      "Candidate artifact root must be a real directory",
    );
  }
  const path = join(root, attemptId + ".patch");
  await writeFile(path, patchBytes, { mode: 0o600, flag: "wx" });
  await chmod(path, 0o600);
  return path;
}

function parseJson<T>(value: string, label: string): T {
  try {
    return JSON.parse(value) as T;
  } catch {
    throw new ControllerError(
      "GITHUB_ACTIONS_ARTIFACT_INVALID",
      label + " is not valid JSON",
    );
  }
}

function assertManifestBinding(
  attempt: StoredAttempt,
  task: ReturnType<ControllerCore["getTask"]>["spec"],
  manifest: ResultManifest,
): void {
  if (
    manifest.attempt_id !== attempt.attempt_id ||
    manifest.attempt_no !== attempt.attempt_no ||
    manifest.task_id !== task.task_id ||
    manifest.base_sha !== task.base_sha ||
    manifest.machine.machine_id !== attempt.machine_id ||
    manifest.harness.adapter !== attempt.harness_adapter ||
    manifest.model.provider !== attempt.model.provider ||
    manifest.model.model !== attempt.model.model ||
    manifest.sandbox.attested !== true ||
    manifest.sandbox.container_runtime !== "github-actions-docker"
  ) {
    throw new ControllerError(
      "GITHUB_ACTIONS_RESULT_BINDING_MISMATCH",
      "GitHub Actions ResultManifest is not bound to the claimed attempt/model/github-hosted boundary",
    );
  }
}

export class GitHubActionsAttemptExecutor {
  readonly #core: ControllerCore;
  readonly #workerRepo: string;
  readonly #workflow: string;
  readonly #dispatchRef: string;
  readonly #workflowSha: string;
  readonly #candidateArtifactRoot: string;
  readonly #qualityProfileRoot: string;
  readonly #pollIntervalMs: number;
  readonly #fetch: typeof fetch;
  readonly #now: () => Date;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #api: GitHubActionsApi;

  constructor(options: GitHubActionsAttemptExecutorOptions) {
    this.#core = options.core;
    this.#workerRepo = options.workerRepo;
    this.#workflow = options.workflow;
    this.#dispatchRef = options.dispatchRef;
    this.#workflowSha = options.workflowSha.toLowerCase();
    this.#candidateArtifactRoot = resolve(options.candidateArtifactRoot);
    this.#qualityProfileRoot = resolve(options.qualityProfileRoot);
    this.#pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_MS;
    this.#fetch = options.fetch ?? trustedGitHubFetch;
    this.#now = options.now ?? (() => new Date());
    this.#sleep =
      options.sleep ??
      (async (ms) => {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
      });
    this.#api =
      options.api ?? new GitHubActionsApi(options.credentials, this.#fetch);

    if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(this.#workerRepo)) {
      throw new ControllerError(
        "GITHUB_ACTIONS_WORKER_REPO_INVALID",
        "workerRepo must be a GitHub owner/repo id",
      );
    }
    if (
      !this.#workflow ||
      !this.#dispatchRef ||
      !/^[0-9a-f]{40}$/.test(this.#workflowSha)
    ) {
      throw new ControllerError(
        "GITHUB_ACTIONS_EXECUTOR_CONFIG_INVALID",
        "workflow, dispatchRef and exact workflowSha are required",
      );
    }
  }

  async execute(attemptId: string): Promise<GitHubActionsAttemptExecutionResult> {
    const attempt = this.#core.getAttempt(attemptId);
    const taskRecord = this.#core.getTask(attempt.task_id);
    const task = taskRecord.spec;
    const { passport } = this.#core.getPassport(task.repo_id);
    const profile: QualityProfile = loadTrustedQualityProfile(
      this.#qualityProfileRoot,
      task.quality_profile,
    );

    if (
      attempt.execution_backend !== "github-actions" ||
      attempt.state !== "LEASED" ||
      taskRecord.state !== "LEASED"
    ) {
      throw new ControllerError(
        "ATTEMPT_STATE_INVALID",
        "GitHub Actions executor requires a github-actions LEASED attempt",
      );
    }
    if (task.archetype === "independent-reviewer" || task.write_scope.length === 0) {
      throw new ControllerError(
        "EXECUTOR_READ_ONLY_FLOW_NOT_READY",
        "Independent review uses the dedicated review backend",
      );
    }

    const observedWorkflowSha = await this.#api.getBranchHead(
      this.#workerRepo,
      this.#dispatchRef,
    );
    if (observedWorkflowSha !== this.#workflowSha) {
      throw new ControllerError(
        "GITHUB_ACTIONS_WORKFLOW_SHA_MISMATCH",
        "Worker-farm dispatch branch does not match the Controller-pinned workflow commit",
        {
          expected: this.#workflowSha,
          observed: observedWorkflowSha,
          workerRepo: this.#workerRepo,
          dispatchRef: this.#dispatchRef,
        },
      );
    }

    const artifactName = "awf-attempt-" + attemptId;
    const dispatch = await this.#api.dispatch({
      workerRepo: this.#workerRepo,
      workflow: this.#workflow,
      ref: this.#dispatchRef,
      inputs: {
        mode: "write",
        attempt_id: attemptId,
        attempt_no: String(attempt.attempt_no),
        machine_id: attempt.machine_id,
        model: attempt.model.model,
        artifact_name: artifactName,
        target_repo: task.repo_id,
        target_owner: task.repo_id.split("/", 1)[0]!,
        target_name: task.repo_id.split("/")[1]!,
        target_visibility: passport.visibility,
        base_sha: task.base_sha,
        task_b64: encodeJson(task),
        passport_b64: encodeJson(passport),
        quality_profile_b64: encodeJson(profile),
      },
    });
    this.#core.beginGitHubActionsProvisioning(attemptId, {
      worker_repo: this.#workerRepo,
      workflow: this.#workflow,
      dispatch_ref: this.#dispatchRef,
      workflow_run_id: dispatch.workflow_run_id,
      run_url: dispatch.run_url,
      workflow_sha: this.#workflowSha,
    });

    const deadline =
      this.#now().getTime() + Math.max(task.lease_ttl_seconds, task.timeout_seconds + 300) * 1000;
    let markedRunning = false;
    let run = await this.#api.getRun(this.#workerRepo, dispatch.workflow_run_id);
    for (;;) {
      if (run.head_sha.toLowerCase() !== this.#workflowSha) {
        try {
          await this.#api.cancelRun(this.#workerRepo, dispatch.workflow_run_id);
        } catch {
          // Preserve supply-chain mismatch as primary failure.
        }
        this.#core.failAttempt(
          attemptId,
          "POLICY_VIOLATION",
          "GITHUB_ACTIONS_WORKFLOW_SHA_MISMATCH",
          null,
          { expected: this.#workflowSha, observed: run.head_sha },
        );
        throw new ControllerError(
          "GITHUB_ACTIONS_WORKFLOW_SHA_MISMATCH",
          "Dispatched workflow run is not executing the Controller-pinned worker-farm commit",
        );
      }
      if (!markedRunning && run.status !== "queued" && run.status !== "requested") {
        this.#core.markGitHubActionsRunning(
          attemptId,
          run.run_started_at ?? run.created_at,
        );
        markedRunning = true;
      }
      if (run.status === "completed") break;
      if (this.#now().getTime() >= deadline) {
        try {
          await this.#api.cancelRun(this.#workerRepo, dispatch.workflow_run_id);
        } catch {
          // Preserve timeout as the primary failure.
        }
        this.#core.failAttempt(
          attemptId,
          "HARNESS_FAILED",
          "GITHUB_ACTIONS_TIMEOUT",
          null,
          { workflow_run_id: dispatch.workflow_run_id },
        );
        throw new ControllerError(
          "GITHUB_ACTIONS_TIMEOUT",
          "GitHub Actions worker exceeded its execution deadline",
        );
      }
      await this.#sleep(this.#pollIntervalMs);
      run = await this.#api.getRun(this.#workerRepo, dispatch.workflow_run_id);
    }

    if (!markedRunning) {
      this.#core.markGitHubActionsRunning(
        attemptId,
        run.run_started_at ?? run.created_at,
      );
      markedRunning = true;
    }
    if (
      run.event !== "workflow_dispatch" ||
      run.path !== ".github/workflows/" + this.#workflow ||
      run.conclusion !== "success"
    ) {
      this.#core.failAttempt(
        attemptId,
        "HARNESS_FAILED",
        "GITHUB_ACTIONS_RUN_FAILED",
        null,
        {
          workflow_run_id: run.id,
          event: run.event,
          path: run.path,
          status: run.status,
          conclusion: run.conclusion,
        },
      );
      throw new ControllerError(
        "GITHUB_ACTIONS_RUN_FAILED",
        "GitHub Actions worker workflow did not complete successfully with the expected identity",
      );
    }

    const artifacts = await this.#api.listRunArtifacts(
      this.#workerRepo,
      run.id,
      artifactName,
    );
    if (artifacts.length !== 1) {
      this.#core.failAttempt(
        attemptId,
        "HARNESS_FAILED",
        "GITHUB_ACTIONS_ARTIFACT_AMBIGUOUS",
        null,
        { workflow_run_id: run.id, artifacts: artifacts.length },
      );
      throw new ControllerError(
        "GITHUB_ACTIONS_ARTIFACT_AMBIGUOUS",
        "Expected exactly one non-expired result artifact for the workflow run",
        { artifacts: artifacts.length },
      );
    }
    const artifact = artifacts[0]!;
    const zipBytes = await this.#api.downloadArtifact(this.#workerRepo, artifact);
    const parsed = await parseGitHubActionsResultArtifact(zipBytes);
    const oidc = await verifyGitHubActionsOidc({
      jwt: parsed.oidcJwt,
      workerRepo: this.#workerRepo,
      workflow: this.#workflow,
      dispatchRef: this.#dispatchRef,
      workflowRunId: run.id,
      workflowRunAttempt: run.run_attempt,
      workflowSha: this.#workflowSha,
      fetch: this.#fetch,
      now: this.#now,
    });

    const receipt = finalizeGitHubActionsExecutionReceipt({
      schema_version: "1.0",
      backend: "github-actions",
      task_id: task.task_id,
      attempt_id: attemptId,
      machine_id: attempt.machine_id,
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
    this.#core.recordGitHubActionsExecutionReceipt(attemptId, receipt);

    const manifest = parseJson<ResultManifest>(parsed.manifestJson, "result-manifest.json");
    assertManifestBinding(attempt, task, manifest);
    if (parsed.patchBytes.byteLength > MAX_PATCH_BYTES) {
      throw new ControllerError(
        "CANDIDATE_PATCH_TOO_LARGE",
        "GitHub Actions candidate patch exceeds Controller limit",
      );
    }
    const patchSha = sha256Bytes(parsed.patchBytes);
    if (manifest.patch_sha256 !== patchSha) {
      throw new ControllerError(
        "PATCH_HASH_MISMATCH",
        "GitHub Actions candidate patch hash does not match ResultManifest",
      );
    }
    const expectedCandidateHash = computeCandidateHash(
      buildCandidateDescriptor(task, manifest),
    );
    if (manifest.candidate_hash !== expectedCandidateHash) {
      throw new ControllerError(
        "CANDIDATE_HASH_MISMATCH",
        "GitHub Actions candidate hash does not match Controller recomputation",
      );
    }
    verifyWorkerManifest(task, passport, manifest, parsed.patchBytes, {
      enforceRequiredQuality: false,
    });

    const patchPath = await persistPatch(
      this.#candidateArtifactRoot,
      attemptId,
      parsed.patchBytes,
    );
    const plan = buildValidationPlanFromQualityProfile({
      task,
      passport,
      candidateHash: manifest.candidate_hash,
      validationWorkspace: "/github-actions/" + String(run.id) + "/verify",
      profile,
    });
    this.#core.beginLocalVerification(attemptId, manifest, patchPath, plan);

    const verificationReport = parseJson<VerificationReport>(
      parsed.verificationReportJson,
      "verification-report.json",
    );
    const completed = this.#core.completeLocalVerification(
      attemptId,
      verificationReport,
    );

    // Keep the source artifact through independent review. It has a one-day
    // retention limit and the review executor deletes it after consuming the
    // exact candidate evidence.

    return {
      attempt: completed,
      manifest,
      patchPath,
      verificationReport,
      workflowRunId: run.id,
    };
  }
}

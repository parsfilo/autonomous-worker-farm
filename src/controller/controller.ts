import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import type {
  GitHubActionsExecutionReceipt,
  GitHubMergeReceipt,
  GitHubPrPublication,
  GitIntegrationArtifact,
  IndependentReviewReport,
  MachineCapability,
  PostMergeVerificationReport,
  RemoteVerificationReport,
  RepoPassport,
  ResultManifest,
  SandboxAttestation,
  TaskSpec,
  ValidationPlan,
  VerificationReport,
  TaskState,
  TaskStateEvent,
} from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";
import { evaluateMachineEligibility, type EligibilityResult } from "../scheduler/eligibility.js";
import { loadOpenCodeFreeRoutingPolicy } from "../models/opencode-free-routing.js";
import {
  loadOpenCodeFreeRuntimeState,
  selectModelFromRuntimeState,
} from "../models/opencode-free-runtime-state.js";
import { verifyIndependentReviewReport } from "../evidence/independent-review.js";
import { verifyGitIntegrationArtifact } from "../repo/git-integration.js";
import { verifyRemoteVerificationReport } from "../repo/remote-verification.js";
import { verifyGitHubMergeReceipt } from "../repo/github-merge-receipt.js";
import { verifyPostMergeVerificationReport } from "../repo/post-merge-verification.js";
import { verifyGitHubActionsExecutionReceipt } from "../execution/github-actions-receipt.js";
import { verifyVerificationReport } from "../quality/verification-report.js";
import { assertTransition } from "../state/state-machine.js";
import {
  FileStateStore,
  type StoredAttempt,
  type StoredRepoSource,
  type StoredReviewRun,
  type StoredTask,
} from "../store/file-store.js";

export interface ControllerOptions {
  statePath: string;
  freeModelPolicyPath?: string;
  freeModelStatePath?: string;
  localVerificationEnabled?: boolean;
  executionBackend?: "local-broker" | "github-actions";
  githubActionsMachineId?: string;
  now?: () => Date;
}

export interface SpawnResult {
  task: StoredTask;
  controllerRevision: number;
  machineEligibility: Record<string, EligibilityResult>;
}

export interface ClaimResult {
  attempt: StoredAttempt;
  task: StoredTask;
  controllerRevision: number;
  machineEligibility: Record<string, EligibilityResult>;
}

const MODEL_RETRY_EXCLUSION_REASONS = new Set([
  "MODEL_RATE_LIMITED",
  "WORKER_TIMEOUT",
  "WORKER_EXIT_NONZERO",
  "EMPTY_WORKER_CHANGE",
]);

function failedModelsForTask(
  attempts: Record<string, StoredAttempt>,
  taskId: string,
): string[] {
  const models = new Set<string>();
  for (const attempt of Object.values(attempts)) {
    if (
      attempt.task_id === taskId &&
      attempt.state === "FAILED" &&
      attempt.failure_reason &&
      MODEL_RETRY_EXCLUSION_REASONS.has(attempt.failure_reason)
    ) {
      models.add(attempt.model.model);
    }
  }
  return [...models].sort();
}


const MODEL_CAPACITY_ATTEMPT_STATES = new Set<StoredAttempt["state"]>([
  "LEASED",
  "PROVISIONING",
  "RUNNING",
]);

const MODEL_CAPACITY_REVIEW_STATES = new Set<StoredReviewRun["state"]>([
  "LEASED",
  "PROVISIONING",
  "RUNNING",
]);

function modelsAtInferenceCapacity(
  attempts: Record<string, StoredAttempt>,
  reviews: Record<string, StoredReviewRun>,
  perModelLimit: number,
): Set<string> {
  const counts = new Map<string, number>();
  const increment = (model: string): void => {
    counts.set(model, (counts.get(model) ?? 0) + 1);
  };

  for (const attempt of Object.values(attempts)) {
    if (
      MODEL_CAPACITY_ATTEMPT_STATES.has(attempt.state) &&
      attempt.slot_released !== true
    ) {
      increment(attempt.model.model);
    }
  }
  for (const review of Object.values(reviews)) {
    if (
      review.model &&
      MODEL_CAPACITY_REVIEW_STATES.has(review.state) &&
      review.slot_released !== true
    ) {
      increment(review.model.model);
    }
  }

  return new Set(
    [...counts.entries()]
      .filter(([, count]) => count >= perModelLimit)
      .map(([model]) => model),
  );
}

export class ControllerCore {
  readonly #contracts: ContractRegistry;
  readonly #store: FileStateStore;
  readonly #freeModelPolicyPath: string | null;
  readonly #freeModelStatePath: string | null;
  readonly #localVerificationEnabled: boolean;
  readonly #executionBackend: "local-broker" | "github-actions";
  readonly #githubActionsMachineId: string | null;
  readonly #now: () => Date;

  constructor(options: ControllerOptions) {
    this.#contracts = new ContractRegistry();
    this.#store = new FileStateStore(options.statePath);
    this.#freeModelPolicyPath = options.freeModelPolicyPath ?? null;
    this.#freeModelStatePath = options.freeModelStatePath ?? null;
    this.#localVerificationEnabled = options.localVerificationEnabled ?? false;
    this.#executionBackend = options.executionBackend ?? "local-broker";
    this.#githubActionsMachineId = options.githubActionsMachineId ?? null;
    if (this.#executionBackend === "github-actions" && !this.#githubActionsMachineId) {
      throw new ControllerError(
        "GITHUB_ACTIONS_MACHINE_UNCONFIGURED",
        "github-actions execution backend requires githubActionsMachineId",
      );
    }
    this.#now = options.now ?? (() => new Date());
    this.#validateLoadedState();
  }

  get revision(): number {
    return this.#store.snapshot.revision;
  }

  registerPassport(input: unknown): { passport: RepoPassport; sha256: string; controllerRevision: number } {
    const passport = this.#contracts.validate<RepoPassport>("repo-passport", input);
    const sha256 = sha256CanonicalJson(passport);

    this.#store.mutate((snapshot) => {
      snapshot.passports[passport.repo_id] = { passport, sha256 };
    });

    return { passport, sha256, controllerRevision: this.revision };
  }

  registerMachine(input: unknown): { machine: MachineCapability; controllerRevision: number } {
    const machine = this.#contracts.validate<MachineCapability>("machine-capability", input);

    this.#store.mutate((snapshot) => {
      const existing = snapshot.machines[machine.machine_id];
      snapshot.machines[machine.machine_id] = {
        ...machine,
        active_slots: existing?.active_slots ?? machine.active_slots ?? 0,
      };
    });

    return { machine, controllerRevision: this.revision };
  }

  registerGitHubPublicSource(repoId: string): {
    source: StoredRepoSource;
    controllerRevision: number;
  } {
    const passport = this.#store.snapshot.passports[repoId];
    if (!passport) {
      throw new ControllerError(
        "REPO_PASSPORT_NOT_FOUND",
        "No Repo Passport registered for " + repoId,
      );
    }
    if (passport.passport.visibility !== "public") {
      throw new ControllerError(
        "REPO_SOURCE_VISIBILITY_MISMATCH",
        "github-public source requires a public Repo Passport",
      );
    }
    if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repoId)) {
      throw new ControllerError("REPO_SOURCE_INVALID", "repo_id is not a safe GitHub owner/repo id");
    }

    const source: StoredRepoSource = {
      repo_id: repoId,
      kind: "github-public",
      remote_url: "https://github.com/" + repoId + ".git",
      registered_at: new Date().toISOString(),
    };

    this.#store.mutate((snapshot) => {
      snapshot.repoSources[repoId] = source;
    });
    return { source, controllerRevision: this.revision };
  }

  getRepoSource(repoId: string): StoredRepoSource {
    const source = this.#store.snapshot.repoSources[repoId];
    if (!source) {
      throw new ControllerError("REPO_SOURCE_NOT_FOUND", "No repo source registered for " + repoId);
    }
    return source;
  }

  getPassport(repoId: string): { passport: RepoPassport; sha256: string } {
    const entry = this.#store.snapshot.passports[repoId];
    if (!entry) throw new ControllerError("REPO_PASSPORT_NOT_FOUND", `No Repo Passport registered for ${repoId}`);
    return entry;
  }

  getTask(taskId: string): StoredTask {
    const task = this.#store.snapshot.tasks[taskId];
    if (!task) throw new ControllerError("TASK_NOT_FOUND", `Task ${taskId} was not found`);
    return task;
  }

  getAttempt(attemptId: string): StoredAttempt {
    const attempt = this.#store.snapshot.attempts[attemptId];
    if (!attempt) {
      throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
    }
    return attempt;
  }

  getReview(reviewId: string): StoredReviewRun {
    const review = this.#store.snapshot.reviews[reviewId];
    if (!review) {
      throw new ControllerError("REVIEW_NOT_FOUND", "Review " + reviewId + " was not found");
    }
    return review;
  }

  beginAttemptProvisioning(
    attemptId: string,
    requestId: string,
    workspaceLeaseId: string,
    runRoot: string,
  ): StoredAttempt {
    if (!requestId || !workspaceLeaseId || !runRoot.startsWith("/")) {
      throw new ControllerError(
        "ATTEMPT_PROVISIONING_BINDING_INVALID",
        "Provisioning requires request, lease and absolute run-root bindings",
      );
    }
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (attempt.state !== "LEASED" || task.state !== "LEASED") {
        throw new ControllerError(
          "ATTEMPT_STATE_INVALID",
          "Attempt must be LEASED before provisioning",
          { attemptState: attempt.state, taskState: task.state },
        );
      }

      assertTransition(task.state, "PROVISIONING");
      const from = task.state;
      task.state = "PROVISIONING";
      task.revision += 1;
      attempt.state = "PROVISIONING";
      attempt.request_id = requestId;
      attempt.workspace_lease_id = workspaceLeaseId;
      attempt.run_root = runRoot;
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attemptId,
        from_state: from,
        to_state: "PROVISIONING",
        reason_code: "SANDBOX_PROVISIONING_STARTED",
        actor_class: "CONTROLLER",
        actor_id: attempt.actor_id,
        at: new Date().toISOString(),
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          request_id: requestId,
          workspace_lease_id: workspaceLeaseId,
          run_root: runRoot,
        },
      });
      return structuredClone(attempt);
    });
  }

  beginGitHubActionsProvisioning(
    attemptId: string,
    dispatch: {
      worker_repo: string;
      workflow: string;
      dispatch_ref: string;
      workflow_run_id: number;
      run_url: string;
      workflow_sha: string;
    },
  ): StoredAttempt {
    if (
      !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(dispatch.worker_repo) ||
      !dispatch.workflow ||
      !dispatch.dispatch_ref ||
      !Number.isInteger(dispatch.workflow_run_id) ||
      dispatch.workflow_run_id < 1 ||
      !dispatch.run_url ||
      !/^[0-9a-f]{40}$/.test(dispatch.workflow_sha)
    ) {
      throw new ControllerError(
        "GITHUB_ACTIONS_DISPATCH_INVALID",
        "GitHub Actions dispatch binding is invalid",
      );
    }
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) {
        throw new ControllerError(
          "ATTEMPT_NOT_FOUND",
          "Attempt " + attemptId + " was not found",
        );
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (
        attempt.execution_backend !== "github-actions" ||
        attempt.state !== "LEASED" ||
        task.state !== "LEASED"
      ) {
        throw new ControllerError(
          "ATTEMPT_STATE_INVALID",
          "GitHub Actions provisioning requires a github-actions LEASED attempt",
          {
            executionBackend: attempt.execution_backend ?? null,
            attemptState: attempt.state,
            taskState: task.state,
          },
        );
      }
      assertTransition(task.state, "PROVISIONING");
      const from = task.state;
      task.state = "PROVISIONING";
      task.revision += 1;
      attempt.state = "PROVISIONING";
      attempt.request_id = "github-actions:" + dispatch.workflow_run_id;
      attempt.github_actions_dispatch = structuredClone(dispatch);
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attemptId,
        from_state: from,
        to_state: "PROVISIONING",
        reason_code: "GITHUB_ACTIONS_DISPATCHED",
        actor_class: "CONTROLLER",
        actor_id: attempt.actor_id,
        at: this.#now().toISOString(),
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          worker_repo: dispatch.worker_repo,
          workflow: dispatch.workflow,
          dispatch_ref: dispatch.dispatch_ref,
          workflow_run_id: dispatch.workflow_run_id,
          run_url: dispatch.run_url,
          workflow_sha: dispatch.workflow_sha,
        },
      });
      return structuredClone(attempt);
    });
  }

  markGitHubActionsRunning(
    attemptId: string,
    startedAt: string,
  ): StoredAttempt {
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) {
        throw new ControllerError(
          "ATTEMPT_NOT_FOUND",
          "Attempt " + attemptId + " was not found",
        );
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (
        attempt.execution_backend !== "github-actions" ||
        attempt.state !== "PROVISIONING" ||
        task.state !== "PROVISIONING" ||
        !attempt.github_actions_dispatch
      ) {
        throw new ControllerError(
          "ATTEMPT_STATE_INVALID",
          "GitHub Actions attempt must be PROVISIONING before RUNNING",
        );
      }
      assertTransition(task.state, "RUNNING");
      const from = task.state;
      task.state = "RUNNING";
      task.revision += 1;
      attempt.state = "RUNNING";
      attempt.started_at = startedAt;
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attemptId,
        from_state: from,
        to_state: "RUNNING",
        reason_code: "GITHUB_ACTIONS_RUN_STARTED",
        actor_class: "CONTROLLER",
        actor_id: attempt.actor_id,
        at: startedAt,
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          workflow_run_id: attempt.github_actions_dispatch.workflow_run_id,
          run_url: attempt.github_actions_dispatch.run_url,
        },
      });
      return structuredClone(attempt);
    });
  }

  recordGitHubActionsExecutionReceipt(
    attemptId: string,
    receiptInput: GitHubActionsExecutionReceipt,
  ): StoredAttempt {
    const receipt = verifyGitHubActionsExecutionReceipt(receiptInput);
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) {
        throw new ControllerError(
          "ATTEMPT_NOT_FOUND",
          "Attempt " + attemptId + " was not found",
        );
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      const dispatch = attempt.github_actions_dispatch;
      if (
        attempt.execution_backend !== "github-actions" ||
        attempt.state !== "RUNNING" ||
        task.state !== "RUNNING" ||
        !dispatch
      ) {
        throw new ControllerError(
          "GITHUB_ACTIONS_RECEIPT_NOT_READY",
          "Execution receipt requires a RUNNING github-actions attempt",
        );
      }
      if (
        receipt.task_id !== task.spec.task_id ||
        receipt.attempt_id !== attemptId ||
        receipt.machine_id !== attempt.machine_id ||
        receipt.worker_repo !== dispatch.worker_repo ||
        receipt.workflow !== dispatch.workflow ||
        receipt.dispatch_ref !== dispatch.dispatch_ref ||
        receipt.workflow_run_id !== dispatch.workflow_run_id ||
        receipt.run_url !== dispatch.run_url ||
        receipt.workflow_sha !== dispatch.workflow_sha
      ) {
        throw new ControllerError(
          "GITHUB_ACTIONS_RECEIPT_BINDING_MISMATCH",
          "GitHub Actions execution receipt is not bound to the dispatched attempt",
        );
      }
      if (attempt.github_actions_execution) {
        if (
          attempt.github_actions_execution.receipt_hash !== receipt.receipt_hash
        ) {
          throw new ControllerError(
            "GITHUB_ACTIONS_RECEIPT_CONFLICT",
            "A different GitHub Actions receipt is already bound to this attempt",
          );
        }
        return structuredClone(attempt);
      }
      attempt.github_actions_execution = structuredClone(receipt);
      return structuredClone(attempt);
    });
  }

  markAttemptRunning(
    attemptId: string,
    attestation: SandboxAttestation,
    startedAt = new Date().toISOString(),
  ): StoredAttempt {
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (attempt.state !== "PROVISIONING" || task.state !== "PROVISIONING") {
        throw new ControllerError(
          "ATTEMPT_STATE_INVALID",
          "Attempt must be PROVISIONING before RUNNING",
          { attemptState: attempt.state, taskState: task.state },
        );
      }
      if (
        attestation.attempt_id !== attemptId ||
        attestation.task_id !== task.spec.task_id ||
        attestation.machine_id !== attempt.machine_id ||
        attestation.status !== "PROVISIONED"
      ) {
        throw new ControllerError(
          "ATTEMPT_ATTESTATION_MISMATCH",
          "Sandbox attestation does not bind to the claimed attempt",
        );
      }

      assertTransition(task.state, "RUNNING");
      const from = task.state;
      task.state = "RUNNING";
      task.revision += 1;
      attempt.state = "RUNNING";
      attempt.started_at = startedAt;
      attempt.sandbox_attestation = structuredClone(attestation);
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attemptId,
        from_state: from,
        to_state: "RUNNING",
        reason_code: "SANDBOX_PROVISIONED",
        actor_class: "CONTROLLER",
        actor_id: attempt.actor_id,
        at: startedAt,
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          request_id: attempt.request_id ?? null,
          broker_build: attestation.broker.build,
          container_id: attestation.container_id ?? null,
        },
      });
      return structuredClone(attempt);
    });
  }

  failAttempt(
    attemptId: string,
    taskState:
      | "HARNESS_FAILED"
      | "MODEL_RATE_LIMITED"
      | "POLICY_VIOLATION"
      | "BASE_DRIFT"
      | "MACHINE_OFFLINE"
      | "LOST",
    reasonCode: string,
    exitCode: number | null = null,
    details: Record<string, unknown> = {},
  ): StoredAttempt {
    const failedAt = this.#now();
    let rateLimitCooldownMs: number | null = null;
    if (reasonCode === "MODEL_RATE_LIMITED" || taskState === "MODEL_RATE_LIMITED") {
      if (!this.#freeModelPolicyPath) {
        throw new ControllerError(
          "FREE_MODEL_RUNTIME_UNCONFIGURED",
          "Cannot persist model rate-limit cooldown without the free-model policy",
        );
      }
      rateLimitCooldownMs = loadOpenCodeFreeRoutingPolicy(
        this.#freeModelPolicyPath,
      ).document.rate_limit_cooldown_ms;
    }

    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (attempt.state === "CANDIDATE" || attempt.state === "FAILED" || attempt.state === "LOST" || attempt.state === "CANCELLED") {
        throw new ControllerError("ATTEMPT_STATE_INVALID", "Attempt is already terminal", { state: attempt.state });
      }

      assertTransition(task.state, taskState);
      const from = task.state;
      task.state = taskState;
      task.revision += 1;
      attempt.state = taskState === "LOST" ? "LOST" : "FAILED";
      attempt.failure_reason = reasonCode;
      attempt.ended_at = failedAt.toISOString();
      attempt.exit_code = exitCode;
      if (rateLimitCooldownMs !== null) {
        snapshot.modelCooldowns[attempt.model.model] = {
          model: attempt.model.model,
          reason: "MODEL_RATE_LIMITED",
          source_attempt_id: attemptId,
          observed_at: failedAt.toISOString(),
          until: new Date(failedAt.getTime() + rateLimitCooldownMs).toISOString(),
        };
      }
      if (!attempt.slot_released) {
        const machine = snapshot.machines[attempt.machine_id];
        if (machine) machine.active_slots = Math.max(0, (machine.active_slots ?? 0) - 1);
        attempt.slot_released = true;
      }
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attemptId,
        from_state: from,
        to_state: taskState,
        reason_code: reasonCode,
        actor_class: "CONTROLLER",
        actor_id: attempt.actor_id,
        at: attempt.ended_at,
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: { ...details, exit_code: exitCode },
      });
      return structuredClone(attempt);
    });
  }

  beginLocalVerification(
    attemptId: string,
    manifest: ResultManifest,
    patchPath: string,
    plan: ValidationPlan,
  ): StoredAttempt {
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) {
        throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (attempt.state !== "RUNNING" || task.state !== "RUNNING") {
        throw new ControllerError(
          "ATTEMPT_STATE_INVALID",
          "Attempt must be RUNNING before local verification",
          { attemptState: attempt.state, taskState: task.state },
        );
      }
      if (
        manifest.attempt_id !== attemptId ||
        manifest.task_id !== task.spec.task_id ||
        manifest.base_sha !== task.spec.base_sha ||
        plan.task_id !== task.spec.task_id ||
        plan.candidate_hash !== manifest.candidate_hash ||
        plan.base_sha !== manifest.base_sha
      ) {
        throw new ControllerError(
          "LOCAL_VERIFICATION_BINDING_MISMATCH",
          "Validation plan/result manifest are not bound to the claimed candidate",
        );
      }
      this.#contracts.validate<ValidationPlan>("validation-plan", plan);

      const sequence: Array<[TaskState, string]> = [
        ["EVIDENCE_COLLECT", "WORKER_EXITED_SUCCESS"],
        ["LOCAL_VERIFY", "EVIDENCE_COLLECTED"],
      ];
      for (const [to, reason] of sequence) {
        assertTransition(task.state, to);
        const from = task.state;
        task.state = to;
        task.revision += 1;
        attempt.state = to as StoredAttempt["state"];
        task.events.push({
          schema_version: "1.0",
          event_id: randomUUID(),
          task_id: task.spec.task_id,
          attempt_id: attemptId,
          from_state: from,
          to_state: to,
          reason_code: reason,
          actor_class: "CONTROLLER",
          actor_id: attempt.actor_id,
          at: manifest.ended_at,
          correlation_id: attempt.correlation_id,
          authoritative_revision: task.revision,
          details:
            to === "LOCAL_VERIFY"
              ? {
                  candidate_hash: manifest.candidate_hash,
                  patch_sha256: manifest.patch_sha256 ?? null,
                  validation_plan_id: plan.plan_id,
                }
              : null,
        });
      }

      attempt.result_manifest = structuredClone(manifest);
      attempt.patch_path = patchPath;
      attempt.validation_plan = structuredClone(plan);
      attempt.verification_report = null;
      attempt.ended_at = manifest.ended_at;
      attempt.exit_code = 0;
      if (!attempt.slot_released) {
        const machine = snapshot.machines[attempt.machine_id];
        if (machine) machine.active_slots = Math.max(0, (machine.active_slots ?? 0) - 1);
        attempt.slot_released = true;
      }
      return structuredClone(attempt);
    });
  }

  completeLocalVerification(
    attemptId: string,
    reportInput: VerificationReport,
  ): StoredAttempt {
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) {
        throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (attempt.state !== "LOCAL_VERIFY" || task.state !== "LOCAL_VERIFY") {
        throw new ControllerError(
          "ATTEMPT_STATE_INVALID",
          "Attempt must be LOCAL_VERIFY before verification completion",
          { attemptState: attempt.state, taskState: task.state },
        );
      }
      if (!attempt.validation_plan || !attempt.result_manifest) {
        throw new ControllerError(
          "LOCAL_VERIFICATION_EVIDENCE_MISSING",
          "Validation plan or candidate manifest is missing",
        );
      }

      const report = verifyVerificationReport(attempt.validation_plan, reportInput);
      if (
        report.task_id !== task.spec.task_id ||
        report.candidate_hash !== attempt.result_manifest.candidate_hash ||
        report.base_sha !== task.spec.base_sha ||
        report.verifier.machine_id !== attempt.machine_id ||
        (attempt.execution_backend === "github-actions" &&
          !attempt.github_actions_execution)
      ) {
        throw new ControllerError(
          "LOCAL_VERIFICATION_BINDING_MISMATCH",
          "Verification report drifted from the candidate",
        );
      }
      attempt.verification_report = structuredClone(report);

      if (report.status !== "PASS") {
        const testsFailed = report.command_results.some(
          (entry) => entry.name === "tests" && entry.exit_code !== 0,
        );
        const to: TaskState = testsFailed ? "TEST_FAILED" : "QUALITY_FAILED";
        assertTransition(task.state, to);
        const from = task.state;
        task.state = to;
        task.revision += 1;
        attempt.state = "FAILED";
        attempt.failure_reason =
          report.status === "ERROR" ? "LOCAL_VERIFICATION_ERROR" : "LOCAL_VERIFICATION_FAILED";
        task.events.push({
          schema_version: "1.0",
          event_id: randomUUID(),
          task_id: task.spec.task_id,
          attempt_id: attemptId,
          from_state: from,
          to_state: to,
          reason_code: attempt.failure_reason,
          actor_class: "CONTROLLER",
          actor_id: attempt.actor_id,
          at: report.ended_at,
          correlation_id: attempt.correlation_id,
          authoritative_revision: task.revision,
          details: {
            verification_report_hash: report.report_hash,
            verification_status: report.status,
          },
        });
        return structuredClone(attempt);
      }

      assertTransition(task.state, "CANDIDATE");
      const from = task.state;
      task.state = "CANDIDATE";
      task.revision += 1;
      attempt.state = "CANDIDATE";
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attemptId,
        from_state: from,
        to_state: "CANDIDATE",
        reason_code:
          attempt.execution_backend === "github-actions"
            ? "GITHUB_ACTIONS_VERIFICATION_PASSED"
            : "LOCAL_VERIFICATION_PASSED",
        actor_class: "CONTROLLER",
        actor_id: attempt.actor_id,
        at: report.ended_at,
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          candidate_hash: attempt.result_manifest.candidate_hash,
          patch_sha256: attempt.result_manifest.patch_sha256 ?? null,
          changed_files: attempt.result_manifest.changed_files,
          verification_report_hash: report.report_hash,
        },
      });
      return structuredClone(attempt);
    });
  }

  promoteAttemptCandidate(
    attemptId: string,
    manifest: ResultManifest,
    patchPath: string,
  ): StoredAttempt {
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Attempt task was not found");
      if (attempt.state !== "RUNNING" || task.state !== "RUNNING") {
        throw new ControllerError(
          "ATTEMPT_STATE_INVALID",
          "Attempt must be RUNNING before candidate promotion",
          { attemptState: attempt.state, taskState: task.state },
        );
      }
      if (manifest.attempt_id !== attemptId || manifest.task_id !== task.spec.task_id) {
        throw new ControllerError(
          "RESULT_MANIFEST_MISMATCH",
          "Result manifest is not bound to the claimed attempt",
        );
      }

      const sequence: Array<[TaskState, string]> = [
        ["EVIDENCE_COLLECT", "WORKER_EXITED_SUCCESS"],
        ["LOCAL_VERIFY", "EVIDENCE_COLLECTED"],
        ["CANDIDATE", "LOCAL_VERIFICATION_PASSED"],
      ];
      for (const [to, reason] of sequence) {
        assertTransition(task.state, to);
        const from = task.state;
        task.state = to;
        task.revision += 1;
        attempt.state = to as StoredAttempt["state"];
        task.events.push({
          schema_version: "1.0",
          event_id: randomUUID(),
          task_id: task.spec.task_id,
          attempt_id: attemptId,
          from_state: from,
          to_state: to,
          reason_code: reason,
          actor_class: "CONTROLLER",
          actor_id: attempt.actor_id,
          at: manifest.ended_at,
          correlation_id: attempt.correlation_id,
          authoritative_revision: task.revision,
          details:
            to === "CANDIDATE"
              ? {
                  candidate_hash: manifest.candidate_hash,
                  patch_sha256: manifest.patch_sha256 ?? null,
                  changed_files: manifest.changed_files,
                }
              : null,
        });
      }

      attempt.result_manifest = structuredClone(manifest);
      attempt.patch_path = patchPath;
      attempt.ended_at = manifest.ended_at;
      attempt.exit_code = 0;
      if (!attempt.slot_released) {
        const machine = snapshot.machines[attempt.machine_id];
        if (machine) machine.active_slots = Math.max(0, (machine.active_slots ?? 0) - 1);
        attempt.slot_released = true;
      }
      return structuredClone(attempt);
    });
  }

  getState(): {
    revision: number;
    tasks: Array<{ task_id: string; repo_id: string; state: TaskState; task_revision: number; attempts: number }>;
    machines: Array<{ machine_id: string; online: boolean; active_slots: number; max_slots: number }>;
    repos: Array<{ repo_id: string; passport_sha256: string }>;
  } {
    const snapshot = this.#store.snapshot;
    return {
      revision: snapshot.revision,
      tasks: Object.values(snapshot.tasks)
        .map((record) => ({
          task_id: record.spec.task_id,
          repo_id: record.spec.repo_id,
          state: record.state,
          task_revision: record.revision,
          attempts: record.attemptCount,
        }))
        .sort((a, b) => a.task_id.localeCompare(b.task_id)),
      machines: Object.values(snapshot.machines)
        .map((machine) => ({
          machine_id: machine.machine_id,
          online: machine.online,
          active_slots: machine.active_slots ?? 0,
          max_slots: machine.max_slots,
        }))
        .sort((a, b) => a.machine_id.localeCompare(b.machine_id)),
      repos: Object.values(snapshot.passports)
        .map(({ passport, sha256 }) => ({ repo_id: passport.repo_id, passport_sha256: sha256 }))
        .sort((a, b) => a.repo_id.localeCompare(b.repo_id)),
    };
  }

  listCapabilities(): {
    machines: MachineCapability[];
    workerArchetypes: TaskSpec["archetype"][];
  } {
    return {
      machines: Object.values(this.#store.snapshot.machines),
      workerArchetypes: [
        "scout",
        "architect",
        "builder",
        "test-engineer",
        "ci-doctor",
        "quality-security",
        "independent-reviewer",
        "domain-specialist",
      ],
    };
  }

  spawn(input: unknown, idempotencyKey: string, expectedRevision?: number): SpawnResult {
    if (!idempotencyKey) throw new ControllerError("IDEMPOTENCY_KEY_REQUIRED", "spawn requires an idempotency key");

    const existing = this.#store.snapshot.idempotency[`SPAWN:${idempotencyKey}`];
    if (existing) return existing as SpawnResult;

    const task = this.#contracts.validate<TaskSpec>("task-spec", input);
    const snapshot = this.#store.snapshot;

    if (expectedRevision !== undefined && expectedRevision !== snapshot.revision) {
      throw new ControllerError(
        "STALE_CONTROLLER_STATE",
        `Expected controller revision ${expectedRevision}, current revision is ${snapshot.revision}`,
        { expectedRevision, currentRevision: snapshot.revision },
      );
    }

    if (snapshot.tasks[task.task_id]) {
      throw new ControllerError("TASK_ALREADY_EXISTS", `Task ${task.task_id} already exists`);
    }

    const passportEntry = snapshot.passports[task.repo_id];
    if (!passportEntry) {
      throw new ControllerError("REPO_PASSPORT_NOT_FOUND", `No Repo Passport registered for ${task.repo_id}`);
    }

    if (passportEntry.sha256 !== task.repo_passport_hash) {
      throw new ControllerError("REPO_PASSPORT_HASH_MISMATCH", "TaskSpec is not bound to the current Repo Passport", {
        expected: passportEntry.sha256,
        received: task.repo_passport_hash,
      });
    }

    if (!passportEntry.passport.allowed_model_classes.includes(task.model_requirements.class)) {
      throw new ControllerError(
        "MODEL_CLASS_DISALLOWED",
        `Model class ${task.model_requirements.class} is not allowed by Repo Passport`,
      );
    }

    const machineEligibility: Record<string, EligibilityResult> = {};
    for (const machine of Object.values(snapshot.machines)) {
      machineEligibility[machine.machine_id] = evaluateMachineEligibility(task, passportEntry.passport, machine);
    }

    const createdAt = new Date().toISOString();
    const record: StoredTask = {
      spec: task,
      state: "READY",
      revision: task.task_revision ?? 1,
      attemptCount: 0,
      events: [
        this.#event(task.task_id, null, "CREATED", "PLANNED", "TASK_VALIDATED", "CONTROLLER", createdAt),
        this.#event(task.task_id, null, "PLANNED", "READY", "PLAN_ACCEPTED", "CONTROLLER", createdAt),
      ],
    };

    let result!: SpawnResult;
    this.#store.mutate((draft) => {
      draft.tasks[task.task_id] = record;
      result = {
        task: structuredClone(record),
        controllerRevision: draft.revision + 1,
        machineEligibility,
      };
      draft.idempotency[`SPAWN:${idempotencyKey}`] = result;
    });
    return result;
  }

  claim(
    taskId: string,
    idempotencyKey: string,
    correlationId: string,
    actorId: string,
    expectedRevision?: number,
  ): ClaimResult {
    if (!idempotencyKey) {
      throw new ControllerError("IDEMPOTENCY_KEY_REQUIRED", "claim requires an idempotency key");
    }
    if (!correlationId || !actorId) {
      throw new ControllerError("CLAIM_ACTOR_REQUIRED", "claim requires correlation_id and actor_id");
    }

    const existing = this.#store.snapshot.idempotency["CLAIM:" + idempotencyKey];
    if (existing) return existing as ClaimResult;

    if (!this.#freeModelPolicyPath || !this.#freeModelStatePath) {
      throw new ControllerError(
        "FREE_MODEL_RUNTIME_UNCONFIGURED",
        "Controller free-model policy/state paths are not configured",
      );
    }
    if (existsSync(this.#freeModelStatePath + ".refreshing")) {
      throw new ControllerError(
        "FREE_MODEL_REFRESH_IN_PROGRESS",
        "OpenCode free-model health refresh is in progress; claim must retry later",
      );
    }

    const policy = loadOpenCodeFreeRoutingPolicy(this.#freeModelPolicyPath);
    const runtimeState = loadOpenCodeFreeRuntimeState(this.#freeModelStatePath, policy, {
      now: this.#now(),
    });
    const now = this.#now();
    let result!: ClaimResult;

    this.#store.mutate((snapshot) => {
      if (expectedRevision !== undefined && expectedRevision !== snapshot.revision) {
        throw new ControllerError(
          "STALE_CONTROLLER_STATE",
          "Expected controller revision " +
            expectedRevision +
            ", current revision is " +
            snapshot.revision,
          { expectedRevision, currentRevision: snapshot.revision },
        );
      }

      const task = snapshot.tasks[taskId];
      if (!task) {
        throw new ControllerError("TASK_NOT_FOUND", "Task " + taskId + " was not found");
      }
      if (task.state !== "READY") {
        throw new ControllerError(
          "TASK_NOT_READY",
          "Task " + taskId + " is " + task.state + ", expected READY",
        );
      }
      if (task.attemptCount >= task.spec.max_attempts) {
        throw new ControllerError(
          "MAX_ATTEMPTS_EXCEEDED",
          "Task " + taskId + " reached max_attempts",
        );
      }

      const passportEntry = snapshot.passports[task.spec.repo_id];
      if (!passportEntry) {
        throw new ControllerError(
          "REPO_PASSPORT_NOT_FOUND",
          "No Repo Passport for " + task.spec.repo_id,
        );
      }

      if (
        passportEntry.passport.visibility !== "public" ||
        (task.spec.model_requirements.privacy_class ?? "public") !== "public"
      ) {
        throw new ControllerError(
          "FREE_MODEL_PRIVACY_BLOCKED",
          "Credentialless public OpenCode models may only receive public-repository public-privacy tasks",
        );
      }
      if (task.spec.network_profile !== "opencode-free") {
        throw new ControllerError(
          "FREE_MODEL_NETWORK_PROFILE_REQUIRED",
          "Credentialless OpenCode execution requires network_profile=opencode-free",
        );
      }

      const requiredQualityGates = Object.entries(passportEntry.passport.quality)
        .filter(([, requirement]) => requirement.required)
        .map(([name]) => name);
      const requiredScannerGates = requiredQualityGates.filter((name) =>
        ["semgrep", "codacy", "sonar"].includes(name),
      );
      if (requiredScannerGates.length > 0) {
        throw new ControllerError(
          "QUALITY_SCANNER_RUNNER_NOT_READY",
          "Automatic claim is disabled until required scanner gates have an isolated verifier",
          { requiredScannerGates },
        );
      }
      if (requiredQualityGates.length > 0 && !this.#localVerificationEnabled) {
        throw new ControllerError(
          "QUALITY_RUNNER_NOT_READY",
          "Automatic claim is disabled until required quality gates have an isolated verifier",
          { requiredQualityGates },
        );
      }

      const supportedEvidence = new Set([
        "sandbox_attestation",
        ...(this.#localVerificationEnabled ? ["tests"] : []),
      ]);
      const unsupportedEvidence = task.spec.evidence_requirements.filter(
        (requirement) => !supportedEvidence.has(requirement),
      );
      if (unsupportedEvidence.length > 0) {
        throw new ControllerError(
          "EVIDENCE_COLLECTOR_NOT_READY",
          "Automatic claim is disabled for evidence types that are not yet collected end-to-end",
          { unsupportedEvidence },
        );
      }

      const activeRepoAttempts = Object.values(snapshot.attempts).filter((attempt) => {
        if (attempt.state !== "LEASED") return false;
        const owner = snapshot.tasks[attempt.task_id];
        return owner?.spec.repo_id === task.spec.repo_id;
      }).length;
      if (activeRepoAttempts >= passportEntry.passport.max_parallel_tasks) {
        throw new ControllerError(
          "REPO_PARALLELISM_LIMIT",
          "Repo has reached max_parallel_tasks",
          {
            repoId: task.spec.repo_id,
            active: activeRepoAttempts,
            limit: passportEntry.passport.max_parallel_tasks,
          },
        );
      }

      const machineEligibility: Record<string, EligibilityResult> = {};
      for (const machine of Object.values(snapshot.machines)) {
        machineEligibility[machine.machine_id] = evaluateMachineEligibility(
          task.spec,
          passportEntry.passport,
          machine,
        );
      }

      const executionMachineId =
        this.#executionBackend === "github-actions"
          ? this.#githubActionsMachineId
          : runtimeState.machine_id;
      const candidates = Object.values(snapshot.machines)
        .filter((machine) => machine.machine_id === executionMachineId)
        .map((machine) => ({
          machine,
          eligibility: machineEligibility[machine.machine_id],
        }))
        .filter(
          (entry) =>
            entry.eligibility?.eligible === true &&
            entry.eligibility.eligibleHarnesses.includes("opencode"),
        )
        .sort((a, b) => {
          const score = (b.eligibility?.score ?? 0) - (a.eligibility?.score ?? 0);
          if (score !== 0) return score;
          return a.machine.machine_id.localeCompare(b.machine.machine_id);
        });

      const selectedMachine = candidates[0];
      if (!selectedMachine) {
        throw new ControllerError(
          "NO_ELIGIBLE_FREE_MODEL_MACHINE",
          "No eligible machine is bound to the fresh OpenCode free runtime evidence",
          {
            machineId: executionMachineId,
            modelHealthMachineId: runtimeState.machine_id,
            executionBackend: this.#executionBackend,
            machineEligibility,
          },
        );
      }

      const diversityAttemptId =
        task.spec.model_requirements.provider_diversity_from_attempt_id ?? null;
      if (task.spec.review_policy.require_provider_diversity && !diversityAttemptId) {
        throw new ControllerError(
          "DIVERSITY_SOURCE_ATTEMPT_REQUIRED",
          "Review policy requires provider/model diversity but TaskSpec has no source attempt id",
        );
      }

      let diversitySourceModel: string | null = null;
      if (diversityAttemptId) {
        const source = snapshot.attempts[diversityAttemptId];
        if (!source) {
          throw new ControllerError(
            "DIVERSITY_SOURCE_ATTEMPT_NOT_FOUND",
            "Diversity source attempt was not found",
            { attemptId: diversityAttemptId },
          );
        }
        const sourceTask = snapshot.tasks[source.task_id];
        if (!sourceTask || sourceTask.spec.repo_id !== task.spec.repo_id) {
          throw new ControllerError(
            "DIVERSITY_SOURCE_REPO_MISMATCH",
            "Diversity source attempt belongs to a different repository",
          );
        }
        diversitySourceModel = source.model.model;
      }

      const excludedModels = new Set(
        failedModelsForTask(snapshot.attempts, task.spec.task_id),
      );
      if (diversitySourceModel) excludedModels.add(diversitySourceModel);

      const cooldownExcludedModels = new Set<string>();
      for (const [cooldownModel, cooldown] of Object.entries(snapshot.modelCooldowns)) {
        const until = Date.parse(cooldown.until);
        if (!Number.isFinite(until) || until <= now.getTime()) {
          delete snapshot.modelCooldowns[cooldownModel];
          continue;
        }
        cooldownExcludedModels.add(cooldownModel);
        excludedModels.add(cooldownModel);
      }

      const capacityExcludedModels = modelsAtInferenceCapacity(
        snapshot.attempts,
        snapshot.reviews,
        policy.document.per_model_max_concurrency,
      );
      for (const capacityModel of capacityExcludedModels) {
        excludedModels.add(capacityModel);
      }

      const model = selectModelFromRuntimeState(
        runtimeState,
        policy,
        task.spec.model_requirements.class,
        [...excludedModels],
      );
      if (!model) {
        throw new ControllerError(
          "NO_HEALTHY_FREE_MODEL",
          "No fresh benchmark-qualified free model is available for the requested class",
          {
            modelClass: task.spec.model_requirements.class,
            excludedModels: [...excludedModels],
            cooldownExcludedModels: [...cooldownExcludedModels],
            capacityExcludedModels: [...capacityExcludedModels],
          },
        );
      }

      const machine = selectedMachine.machine;
      const attemptNo = task.attemptCount + 1;
      const attemptId = "attempt-" + randomUUID();
      const leasedAt = now.toISOString();
      const expiresAt = new Date(
        now.getTime() + task.spec.lease_ttl_seconds * 1000,
      ).toISOString();

      const attempt: StoredAttempt = {
        attempt_id: attemptId,
        task_id: taskId,
        attempt_no: attemptNo,
        machine_id: machine.machine_id,
        harness_adapter: "opencode",
        model: {
          provider: "opencode",
          model,
        },
        state: "LEASED",
        leased_at: leasedAt,
        expires_at: expiresAt,
        correlation_id: correlationId,
        actor_id: actorId,
        diversity_source_attempt_id: diversityAttemptId,
        execution_backend: this.#executionBackend,
        slot_released: false,
      };

      assertTransition(task.state, "LEASED");
      const from = task.state;
      task.state = "LEASED";
      task.revision += 1;
      task.attemptCount = attemptNo;
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: taskId,
        attempt_id: attemptId,
        from_state: from,
        to_state: "LEASED",
        reason_code: "ATTEMPT_CLAIMED",
        actor_class: "CONTROLLER",
        actor_id: actorId,
        at: leasedAt,
        correlation_id: correlationId,
        authoritative_revision: task.revision,
        details: {
          machine_id: machine.machine_id,
          harness_adapter: "opencode",
          model_provider: "opencode",
          model,
          expires_at: expiresAt,
          diversity_source_attempt_id: diversityAttemptId,
          execution_backend: this.#executionBackend,
          model_health_machine_id: runtimeState.machine_id,
        },
      });

      machine.active_slots = (machine.active_slots ?? 0) + 1;
      snapshot.attempts[attemptId] = attempt;

      result = {
        attempt: structuredClone(attempt),
        task: structuredClone(task),
        controllerRevision: snapshot.revision + 1,
        machineEligibility,
      };
      snapshot.idempotency["CLAIM:" + idempotencyKey] = result;
    });

    return result;
  }

  evaluateEligibility(taskId: string): Record<string, EligibilityResult> {
    const snapshot = this.#store.snapshot;
    const task = snapshot.tasks[taskId];
    if (!task) throw new ControllerError("TASK_NOT_FOUND", `Task ${taskId} was not found`);
    const passport = snapshot.passports[task.spec.repo_id];
    if (!passport) throw new ControllerError("REPO_PASSPORT_NOT_FOUND", `No Repo Passport for ${task.spec.repo_id}`);

    return Object.fromEntries(
      Object.values(snapshot.machines).map((machine) => [
        machine.machine_id,
        evaluateMachineEligibility(task.spec, passport.passport, machine),
      ]),
    );
  }

  transition(
    taskId: string,
    to: TaskState,
    reasonCode: string,
    actorClass: TaskStateEvent["actor_class"],
    correlationId: string,
    actorId?: string,
  ): StoredTask {
    const result = this.#store.mutate((snapshot) => {
      const task = snapshot.tasks[taskId];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", `Task ${taskId} was not found`);

      assertTransition(task.state, to);
      const from = task.state;
      task.state = to;
      task.revision += 1;
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: taskId,
        attempt_id: null,
        from_state: from,
        to_state: to,
        reason_code: reasonCode,
        actor_class: actorClass,
        ...(actorId ? { actor_id: actorId } : {}),
        at: new Date().toISOString(),
        correlation_id: correlationId,
        authoritative_revision: task.revision,
      });
      return structuredClone(task);
    });

    return result;
  }

  cancel(taskId: string, correlationId: string, actorId: string): StoredTask {
    const task = this.getTask(taskId);
    if (task.state === "CANCELLED") return task;
    if (task.state === "DONE") {
      throw new ControllerError("TASK_TERMINAL", "Completed tasks cannot be cancelled");
    }
    return this.transition(taskId, "CANCELLED", "CANCEL_REQUESTED", "MASTER", correlationId, actorId);
  }

  retry(taskId: string, correlationId: string, actorId: string): StoredTask {
    const task = this.getTask(taskId);
    if (task.attemptCount >= task.spec.max_attempts) {
      throw new ControllerError("MAX_ATTEMPTS_EXCEEDED", `Task ${taskId} reached max_attempts`);
    }
    return this.transition(taskId, "READY", "RETRY_REQUESTED", "MASTER", correlationId, actorId);
  }

  requestReview(
    taskId: string,
    candidateHash: string,
    correlationId: string,
    actorId: string,
  ): StoredReviewRun {
    if (!/^[0-9a-f]{64}$/.test(candidateHash)) {
      throw new ControllerError("CANDIDATE_HASH_INVALID", "Independent review requires exact candidate hash");
    }
    return this.#store.mutate((snapshot) => {
      const task = snapshot.tasks[taskId];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Task " + taskId + " was not found");
      if (task.state !== "CANDIDATE") {
        throw new ControllerError(
          "REVIEW_GATE_NOT_READY",
          "Independent review requires task state CANDIDATE",
          { state: task.state },
        );
      }
      const sourceAttempts = Object.values(snapshot.attempts).filter(
        (attempt) =>
          attempt.task_id === taskId &&
          attempt.state === "CANDIDATE" &&
          attempt.result_manifest?.candidate_hash === candidateHash,
      );
      if (sourceAttempts.length !== 1) {
        throw new ControllerError(
          "REVIEW_CANDIDATE_NOT_FOUND",
          "Exact candidate hash did not resolve to one candidate-producing attempt",
          { candidateHash, matches: sourceAttempts.length },
        );
      }
      const source = sourceAttempts[0]!;
      const patchSha = source.result_manifest?.patch_sha256;
      if (!patchSha || !source.patch_path) {
        throw new ControllerError(
          "REVIEW_CANDIDATE_EVIDENCE_MISSING",
          "Candidate patch evidence is missing",
        );
      }

      assertTransition(task.state, "INDEPENDENT_REVIEW");
      const from = task.state;
      task.state = "INDEPENDENT_REVIEW";
      task.revision += 1;

      const reviewId = "review-" + randomUUID();
      const createdAt = new Date().toISOString();
      const review: StoredReviewRun = {
        review_id: reviewId,
        task_id: taskId,
        source_attempt_id: source.attempt_id,
        candidate_hash: candidateHash,
        patch_sha256: patchSha,
        state: "READY",
        correlation_id: correlationId,
        actor_id: actorId,
        created_at: createdAt,
        slot_released: true,
      };
      snapshot.reviews[reviewId] = review;
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: taskId,
        attempt_id: source.attempt_id,
        from_state: from,
        to_state: "INDEPENDENT_REVIEW",
        reason_code: "REVIEW_REQUESTED",
        actor_class: "MASTER",
        actor_id: actorId,
        at: createdAt,
        correlation_id: correlationId,
        authoritative_revision: task.revision,
        details: {
          review_id: reviewId,
          candidate_hash: candidateHash,
          source_attempt_id: source.attempt_id,
        },
      });
      return structuredClone(review);
    });
  }

  claimReview(
    reviewId: string,
    correlationId: string,
    actorId: string,
  ): StoredReviewRun {
    if (!this.#freeModelPolicyPath || !this.#freeModelStatePath) {
      throw new ControllerError(
        "FREE_MODEL_RUNTIME_UNCONFIGURED",
        "Controller free-model policy/state paths are not configured",
      );
    }
    if (existsSync(this.#freeModelStatePath + ".refreshing")) {
      throw new ControllerError(
        "FREE_MODEL_REFRESH_IN_PROGRESS",
        "OpenCode free-model health refresh is in progress; review claim must retry later",
      );
    }
    const policy = loadOpenCodeFreeRoutingPolicy(this.#freeModelPolicyPath);
    const runtimeState = loadOpenCodeFreeRuntimeState(this.#freeModelStatePath, policy, {
      now: this.#now(),
    });
    const now = this.#now();

    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (!review) throw new ControllerError("REVIEW_NOT_FOUND", "Review " + reviewId + " was not found");
      if (review.state !== "READY") {
        throw new ControllerError("REVIEW_NOT_READY", "Review is not READY", { state: review.state });
      }
      const task = snapshot.tasks[review.task_id];
      if (!task || task.state !== "INDEPENDENT_REVIEW") {
        throw new ControllerError("REVIEW_TASK_STATE_INVALID", "Task is not awaiting independent review");
      }
      const source = snapshot.attempts[review.source_attempt_id];
      if (!source?.result_manifest || source.result_manifest.candidate_hash !== review.candidate_hash) {
        throw new ControllerError("REVIEW_SOURCE_DRIFT", "Source candidate evidence changed or disappeared");
      }
      const passportEntry = snapshot.passports[task.spec.repo_id];
      if (!passportEntry) throw new ControllerError("REPO_PASSPORT_NOT_FOUND", "Repo Passport missing");

      const reviewSpec: TaskSpec = structuredClone(task.spec);
      reviewSpec.archetype = "independent-reviewer";
      reviewSpec.write_scope = [];
      reviewSpec.model_requirements = {
        ...reviewSpec.model_requirements,
        class: "review",
        privacy_class: "public",
        provider_diversity_from_attempt_id: source.attempt_id,
      };
      reviewSpec.evidence_requirements = ["sandbox_attestation"];

      const reviewMachineId =
        this.#executionBackend === "github-actions"
          ? this.#githubActionsMachineId
          : runtimeState.machine_id;
      const machine = reviewMachineId
        ? snapshot.machines[reviewMachineId]
        : undefined;
      if (!machine) {
        throw new ControllerError(
          "NO_ELIGIBLE_FREE_MODEL_MACHINE",
          "Configured review execution machine is not registered",
          {
            executionBackend: this.#executionBackend,
            executionMachineId: reviewMachineId,
            modelHealthMachineId: runtimeState.machine_id,
          },
        );
      }
      const eligibility = evaluateMachineEligibility(reviewSpec, passportEntry.passport, machine);
      if (!eligibility.eligible || !eligibility.eligibleHarnesses.includes("opencode")) {
        throw new ControllerError("NO_ELIGIBLE_FREE_MODEL_MACHINE", "Runtime-evidence machine is not eligible for review", {
          reasons: eligibility.reasons,
        });
      }
      const reviewExcludedModels = new Set<string>([source.model.model]);
      const capacityExcludedModels = modelsAtInferenceCapacity(
        snapshot.attempts,
        snapshot.reviews,
        policy.document.per_model_max_concurrency,
      );
      for (const capacityModel of capacityExcludedModels) {
        reviewExcludedModels.add(capacityModel);
      }

      const model = selectModelFromRuntimeState(
        runtimeState,
        policy,
        "review",
        [...reviewExcludedModels],
      );
      if (!model) {
        throw new ControllerError("NO_HEALTHY_FREE_MODEL", "No model-diverse healthy review model is available");
      }
      if ((machine.active_slots ?? 0) >= machine.max_slots) {
        throw new ControllerError("NO_CAPACITY", "Review machine has no free execution slot");
      }

      review.state = "LEASED";
      review.execution_backend = this.#executionBackend;
      review.machine_id = machine.machine_id;
      review.model = { provider: "opencode", model };
      review.leased_at = now.toISOString();
      review.expires_at = new Date(now.getTime() + task.spec.lease_ttl_seconds * 1000).toISOString();
      review.correlation_id = correlationId;
      review.actor_id = actorId;
      review.slot_released = false;
      machine.active_slots = (machine.active_slots ?? 0) + 1;
      return structuredClone(review);
    });
  }

  beginGitHubActionsReviewProvisioning(
    reviewId: string,
    dispatch: {
      worker_repo: string;
      workflow: string;
      dispatch_ref: string;
      workflow_run_id: number;
      run_url: string;
      workflow_sha: string;
    },
    requestHash: string,
  ): StoredReviewRun {
    if (!/^[0-9a-f]{64}$/.test(requestHash)) {
      throw new ControllerError(
        "REVIEW_SANDBOX_BINDING_INVALID",
        "GitHub Actions review requires a canonical request binding hash",
      );
    }
    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (
        !review ||
        review.execution_backend !== "github-actions" ||
        review.state !== "LEASED"
      ) {
        throw new ControllerError(
          "REVIEW_STATE_INVALID",
          "GitHub Actions review must be LEASED before provisioning",
        );
      }
      if (
        !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(dispatch.worker_repo) ||
        !dispatch.workflow ||
        !dispatch.dispatch_ref ||
        !Number.isInteger(dispatch.workflow_run_id) ||
        dispatch.workflow_run_id < 1 ||
        !dispatch.run_url ||
        !/^[0-9a-f]{40}$/.test(dispatch.workflow_sha)
      ) {
        throw new ControllerError(
          "GITHUB_ACTIONS_DISPATCH_INVALID",
          "GitHub Actions review dispatch binding is invalid",
        );
      }
      review.state = "PROVISIONING";
      review.request_id = "github-actions:" + dispatch.workflow_run_id;
      review.sandbox_request_hash = requestHash;
      review.workspace_read_only = true;
      review.github_actions_dispatch = structuredClone(dispatch);
      return structuredClone(review);
    });
  }

  markGitHubActionsReviewRunning(
    reviewId: string,
    startedAt: string,
  ): StoredReviewRun {
    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (
        !review ||
        review.execution_backend !== "github-actions" ||
        review.state !== "PROVISIONING" ||
        !review.github_actions_dispatch ||
        review.workspace_read_only !== true
      ) {
        throw new ControllerError(
          "REVIEW_STATE_INVALID",
          "GitHub Actions review must be PROVISIONING before RUNNING",
        );
      }
      review.state = "RUNNING";
      review.started_at = startedAt;
      return structuredClone(review);
    });
  }

  recordGitHubActionsReviewExecutionReceipt(
    reviewId: string,
    receiptInput: GitHubActionsExecutionReceipt,
  ): StoredReviewRun {
    const receipt = verifyGitHubActionsExecutionReceipt(receiptInput);
    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (
        !review ||
        review.execution_backend !== "github-actions" ||
        review.state !== "RUNNING" ||
        !review.machine_id ||
        !review.github_actions_dispatch
      ) {
        throw new ControllerError(
          "GITHUB_ACTIONS_RECEIPT_NOT_READY",
          "Review execution receipt requires a RUNNING github-actions review",
        );
      }
      const task = snapshot.tasks[review.task_id];
      if (!task) {
        throw new ControllerError("TASK_NOT_FOUND", "Review task was not found");
      }
      const dispatch = review.github_actions_dispatch;
      if (
        receipt.task_id !== task.spec.task_id ||
        receipt.attempt_id !== reviewId ||
        receipt.machine_id !== review.machine_id ||
        receipt.worker_repo !== dispatch.worker_repo ||
        receipt.workflow !== dispatch.workflow ||
        receipt.dispatch_ref !== dispatch.dispatch_ref ||
        receipt.workflow_run_id !== dispatch.workflow_run_id ||
        receipt.run_url !== dispatch.run_url ||
        receipt.workflow_sha !== dispatch.workflow_sha
      ) {
        throw new ControllerError(
          "GITHUB_ACTIONS_RECEIPT_BINDING_MISMATCH",
          "GitHub Actions review receipt is not bound to the dispatched review",
        );
      }
      review.github_actions_execution = structuredClone(receipt);
      return structuredClone(review);
    });
  }

  beginReviewProvisioning(
    reviewId: string,
    requestId: string,
    workspaceLeaseId: string,
    runRoot: string,
    requestHash: string,
    workspaceReadOnly: true,
  ): StoredReviewRun {
    if (!/^[0-9a-f]{64}$/.test(requestHash) || workspaceReadOnly !== true) {
      throw new ControllerError(
        "REVIEW_SANDBOX_BINDING_INVALID",
        "Review provisioning requires an exact read-only SandboxRequest hash",
      );
    }
    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (!review || review.state !== "LEASED") {
        throw new ControllerError("REVIEW_STATE_INVALID", "Review must be LEASED before provisioning");
      }
      review.state = "PROVISIONING";
      review.request_id = requestId;
      review.workspace_lease_id = workspaceLeaseId;
      review.run_root = runRoot;
      review.sandbox_request_hash = requestHash;
      review.workspace_read_only = true;
      return structuredClone(review);
    });
  }

  markReviewRunning(
    reviewId: string,
    attestation: SandboxAttestation,
    startedAt = new Date().toISOString(),
  ): StoredReviewRun {
    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (!review || review.state !== "PROVISIONING") {
        throw new ControllerError("REVIEW_STATE_INVALID", "Review must be PROVISIONING before RUNNING");
      }
      if (
        attestation.attempt_id !== reviewId ||
        attestation.task_id !== review.task_id ||
        attestation.machine_id !== review.machine_id ||
        attestation.status !== "PROVISIONED" ||
        review.workspace_read_only !== true ||
        !review.sandbox_request_hash ||
        attestation.request_hash !== review.sandbox_request_hash
      ) {
        throw new ControllerError("REVIEW_ATTESTATION_MISMATCH", "Review sandbox attestation binding mismatch");
      }
      review.state = "RUNNING";
      review.started_at = startedAt;
      review.sandbox_attestation = structuredClone(attestation);
      return structuredClone(review);
    });
  }

  completeReview(reviewId: string, report: IndependentReviewReport): StoredReviewRun {
    verifyIndependentReviewReport(report);
    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (!review || review.state !== "RUNNING") {
        throw new ControllerError("REVIEW_STATE_INVALID", "Review must be RUNNING before completion");
      }
      const task = snapshot.tasks[review.task_id];
      if (!task || task.state !== "INDEPENDENT_REVIEW") {
        throw new ControllerError("REVIEW_TASK_STATE_INVALID", "Task is not awaiting independent review");
      }
      if (
        report.review_id !== reviewId ||
        report.review_attempt_id !== reviewId ||
        report.task_id !== review.task_id ||
        report.source_attempt_id !== review.source_attempt_id ||
        report.candidate_hash !== review.candidate_hash ||
        report.patch_sha256 !== review.patch_sha256 ||
        report.reviewer.machine_id !== review.machine_id ||
        report.reviewer.model !== review.model?.model ||
        review.workspace_read_only !== true ||
        report.sandbox.workspace_read_only !== true ||
        report.sandbox.request_hash !== review.sandbox_request_hash ||
        (review.execution_backend === "github-actions"
          ? !review.github_actions_execution
          : report.sandbox.request_hash !== review.sandbox_attestation?.request_hash ||
            report.sandbox.image_digest !== review.sandbox_attestation?.image_digest)
      ) {
        throw new ControllerError("REVIEW_REPORT_BINDING_MISMATCH", "Review report binding mismatch");
      }

      const to: TaskState = report.verdict === "PASS" ? "REMOTE_VERIFY" : "REVIEW_BLOCKED";
      assertTransition(task.state, to);
      const from = task.state;
      task.state = to;
      task.revision += 1;
      review.state = report.verdict === "PASS" ? "SUCCEEDED" : "BLOCKED";
      review.report = structuredClone(report);
      review.ended_at = report.ended_at;
      review.exit_code = 0;
      if (!review.slot_released && review.machine_id) {
        const machine = snapshot.machines[review.machine_id];
        if (machine) machine.active_slots = Math.max(0, (machine.active_slots ?? 0) - 1);
        review.slot_released = true;
      }
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: review.source_attempt_id,
        from_state: from,
        to_state: to,
        reason_code: report.verdict === "PASS" ? "INDEPENDENT_REVIEW_PASSED" : "INDEPENDENT_REVIEW_BLOCKED",
        actor_class: "REVIEWER",
        actor_id: review.actor_id,
        at: report.ended_at,
        correlation_id: review.correlation_id,
        authoritative_revision: task.revision,
        details: {
          review_id: reviewId,
          review_report_hash: report.report_hash,
          candidate_hash: report.candidate_hash,
          reviewer_model: report.reviewer.model,
          findings: report.findings.length,
        },
      });
      return structuredClone(review);
    });
  }

  failReview(reviewId: string, reason: string, exitCode: number | null = null): StoredReviewRun {
    return this.#store.mutate((snapshot) => {
      const review = snapshot.reviews[reviewId];
      if (!review || !["LEASED", "PROVISIONING", "RUNNING"].includes(review.state)) {
        throw new ControllerError("REVIEW_STATE_INVALID", "Review is not active");
      }
      review.state = "FAILED";
      review.ended_at = new Date().toISOString();
      review.exit_code = exitCode;
      review.failure_reason = reason;
      if (!review.slot_released && review.machine_id) {
        const machine = snapshot.machines[review.machine_id];
        if (machine) machine.active_slots = Math.max(0, (machine.active_slots ?? 0) - 1);
        review.slot_released = true;
      }
      return structuredClone(review);
    });
  }

  recordGitIntegrationArtifact(
    attemptId: string,
    artifactInput: GitIntegrationArtifact,
  ): StoredAttempt {
    const artifact = verifyGitIntegrationArtifact(artifactInput);
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) {
        throw new ControllerError("ATTEMPT_NOT_FOUND", "Attempt " + attemptId + " was not found");
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Integration task was not found");
      if (task.state !== "REMOTE_VERIFY" || attempt.state !== "CANDIDATE") {
        throw new ControllerError(
          "GIT_INTEGRATION_NOT_READY",
          "Git integration artifact may only be recorded after successful independent review",
          { taskState: task.state, attemptState: attempt.state },
        );
      }
      const manifest = attempt.result_manifest;
      if (!manifest || !manifest.patch_sha256) {
        throw new ControllerError("GIT_INTEGRATION_EVIDENCE_MISSING", "Candidate manifest/patch evidence is missing");
      }
      const review = Object.values(snapshot.reviews).find(
        (entry) =>
          entry.task_id === task.spec.task_id &&
          entry.source_attempt_id === attemptId &&
          entry.state === "SUCCEEDED" &&
          entry.report?.verdict === "PASS" &&
          entry.candidate_hash === manifest.candidate_hash,
      );
      if (!review) {
        throw new ControllerError(
          "GIT_INTEGRATION_REVIEW_MISSING",
          "No successful independent review is bound to this candidate",
        );
      }
      if (
        artifact.task_id !== task.spec.task_id ||
        artifact.attempt_id !== attemptId ||
        artifact.repo_id !== task.spec.repo_id ||
        artifact.base_sha !== task.spec.base_sha ||
        artifact.candidate_hash !== manifest.candidate_hash ||
        artifact.patch_sha256 !== manifest.patch_sha256 ||
        JSON.stringify([...artifact.changed_files].sort()) !==
          JSON.stringify([...manifest.changed_files].sort())
      ) {
        throw new ControllerError(
          "GIT_INTEGRATION_BINDING_MISMATCH",
          "Git integration artifact is not bound to the reviewed candidate",
        );
      }
      if (attempt.integration_candidate) {
        if (attempt.integration_candidate.artifact_hash !== artifact.artifact_hash) {
          throw new ControllerError(
            "GIT_INTEGRATION_ARTIFACT_CONFLICT",
            "A different integration artifact is already bound to this attempt",
          );
        }
        return structuredClone(attempt);
      }
      attempt.integration_candidate = structuredClone(artifact);
      return structuredClone(attempt);
    });
  }

  recordPublishedPullRequest(
    attemptId: string,
    publicationInput: GitHubPrPublication,
  ): StoredAttempt {
    const publication = this.#contracts.validate<GitHubPrPublication>(
      "github-pr-publication",
      publicationInput,
    );
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[attemptId];
      if (!attempt) {
        throw new ControllerError(
          "ATTEMPT_NOT_FOUND",
          "Attempt " + attemptId + " was not found",
        );
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) {
        throw new ControllerError(
          "TASK_NOT_FOUND",
          "Pull request task was not found",
        );
      }
      if (task.state !== "REMOTE_VERIFY" || attempt.state !== "CANDIDATE") {
        throw new ControllerError(
          "PR_GATE_NOT_READY",
          "Pull request publication requires a reviewed candidate in REMOTE_VERIFY",
          { taskState: task.state, attemptState: attempt.state },
        );
      }
      const integration = attempt.integration_candidate;
      if (!integration) {
        throw new ControllerError(
          "PR_INTEGRATION_CANDIDATE_NOT_READY",
          "Deterministic integration candidate is missing",
        );
      }
      const expectedBranch =
        "awf/candidate-" + integration.candidate_hash.slice(0, 24);
      if (
        publication.provider !== "github" ||
        publication.repo_id !== task.spec.repo_id ||
        publication.task_id !== task.spec.task_id ||
        publication.attempt_id !== attemptId ||
        publication.integration_artifact_hash !== integration.artifact_hash ||
        publication.branch !== expectedBranch ||
        publication.base_ref !== task.spec.base_ref ||
        publication.base_sha !== task.spec.base_sha ||
        publication.head_sha !== integration.commit_sha
      ) {
        throw new ControllerError(
          "PR_PUBLICATION_BINDING_MISMATCH",
          "Published pull request is not bound to the deterministic integration candidate",
        );
      }
      if (attempt.pull_request) {
        if (
          sha256CanonicalJson(attempt.pull_request) !==
          sha256CanonicalJson(publication)
        ) {
          throw new ControllerError(
            "PR_PUBLICATION_CONFLICT",
            "A different pull request publication is already bound to this attempt",
          );
        }
        return structuredClone(attempt);
      }
      attempt.pull_request = structuredClone(publication);
      return structuredClone(attempt);
    });
  }

  getPrIntegrationCandidate(taskId: string): StoredAttempt {
    const snapshot = this.#store.snapshot;
    const task = snapshot.tasks[taskId];
    if (!task) {
      throw new ControllerError(
        "TASK_NOT_FOUND",
        "Task " + taskId + " was not found",
      );
    }
    const candidates = Object.values(snapshot.attempts).filter(
      (attempt) =>
        attempt.task_id === taskId &&
        attempt.state === "CANDIDATE" &&
        attempt.integration_candidate,
    );
    if (candidates.length !== 1) {
      throw new ControllerError(
        "PR_INTEGRATION_CANDIDATE_NOT_READY",
        "Expected exactly one deterministic integration candidate for task",
        { taskId, candidates: candidates.length },
      );
    }
    return structuredClone(candidates[0]!);
  }

  completeRemoteVerification(reportInput: RemoteVerificationReport): StoredTask {
    const report = verifyRemoteVerificationReport(reportInput);
    if (report.status === "PENDING") {
      throw new ControllerError(
        "REMOTE_VERIFICATION_PENDING",
        "Remote verification is still waiting for exact-SHA checks",
      );
    }
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[report.attempt_id];
      if (!attempt) {
        throw new ControllerError(
          "ATTEMPT_NOT_FOUND",
          "Attempt " + report.attempt_id + " was not found",
        );
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) throw new ControllerError("TASK_NOT_FOUND", "Remote verification task was not found");
      if (attempt.remote_verification_report) {
        if (attempt.remote_verification_report.report_hash !== report.report_hash) {
          throw new ControllerError(
            "REMOTE_VERIFICATION_REPORT_CONFLICT",
            "A different remote verification report is already bound to this attempt",
          );
        }
        return structuredClone(task);
      }
      if (task.state !== "REMOTE_VERIFY" || attempt.state !== "CANDIDATE") {
        throw new ControllerError(
          "REMOTE_VERIFICATION_NOT_READY",
          "Remote verification requires a reviewed candidate in REMOTE_VERIFY",
          { taskState: task.state, attemptState: attempt.state },
        );
      }
      const integration = attempt.integration_candidate;
      const publication = attempt.pull_request;
      const manifest = attempt.result_manifest;
      if (!integration || !publication || !manifest) {
        throw new ControllerError(
          "REMOTE_VERIFICATION_INTEGRATION_MISSING",
          "Deterministic Git integration artifact and persisted PR publication are required before remote verification",
        );
      }
      if (
        report.task_id !== task.spec.task_id ||
        report.attempt_id !== attempt.attempt_id ||
        report.repo_id !== task.spec.repo_id ||
        report.candidate_hash !== manifest.candidate_hash ||
        report.integration_artifact_hash !== integration.artifact_hash ||
        report.expected_base_sha !== task.spec.base_sha ||
        report.expected_commit_sha !== integration.commit_sha ||
        report.base_ref !== task.spec.base_ref ||
        report.pr_number !== publication.pr_number
      ) {
        throw new ControllerError(
          "REMOTE_VERIFICATION_BINDING_MISMATCH",
          "Remote verification report is not bound to the deterministic reviewed integration candidate",
        );
      }

      const to: TaskState =
        report.status === "PASS"
          ? "READY_TO_MERGE"
          : report.status === "BASE_DRIFT"
            ? "BASE_DRIFT"
            : report.status === "QUALITY_FAILED"
              ? "QUALITY_FAILED"
              : "EXTERNAL_BLOCKER";
      assertTransition(task.state, to);
      const from = task.state;
      task.state = to;
      task.revision += 1;
      attempt.remote_verification_report = structuredClone(report);
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attempt.attempt_id,
        from_state: from,
        to_state: to,
        reason_code:
          report.status === "PASS"
            ? "REMOTE_EXACT_SHA_VERIFIED"
            : "REMOTE_" + report.status,
        actor_class: "CONTROLLER",
        actor_id: report.observer.build,
        at: report.observed_at,
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          pr_number: report.pr_number,
          pr_head_ref: report.pr_head_ref,
          observed_pr_head_sha: report.observed_pr_head_sha,
          expected_commit_sha: integration.commit_sha,
          remote_verification_report_hash: report.report_hash,
          remote_checks: report.remote_checks.length,
        },
      });
      return structuredClone(task);
    });
  }

  requestPr(taskId: string, correlationId: string, actorId: string): StoredTask {
    const task = this.getTask(taskId);
    if (task.state !== "REMOTE_VERIFY") {
      throw new ControllerError(
        "PR_GATE_NOT_READY",
        "PR request requires a reviewed candidate waiting in REMOTE_VERIFY",
        { state: task.state },
      );
    }
    this.getPrIntegrationCandidate(taskId);
    return task;
  }

  requestMerge(taskId: string, correlationId: string, actorId: string): StoredTask {
    const task = this.getTask(taskId);
    if (task.state !== "READY_TO_MERGE") {
      throw new ControllerError(
        "MERGE_GATE_NOT_READY",
        `Task state ${task.state} is not READY_TO_MERGE`,
      );
    }
    const candidate = this.getPrIntegrationCandidate(taskId);
    if (
      !candidate.integration_candidate ||
      !candidate.pull_request ||
      candidate.remote_verification_report?.status !== "PASS"
    ) {
      throw new ControllerError(
        "MERGE_EVIDENCE_NOT_READY",
        "Merge requires deterministic integration, persisted PR publication, and trusted exact-SHA remote PASS evidence",
      );
    }

    return this.#store.mutate((snapshot) => {
      const stored = snapshot.tasks[taskId];
      if (!stored) {
        throw new ControllerError("TASK_NOT_FOUND", `Task ${taskId} was not found`);
      }
      if (stored.state !== "READY_TO_MERGE") {
        throw new ControllerError(
          "MERGE_GATE_NOT_READY",
          `Task state ${stored.state} is not READY_TO_MERGE`,
        );
      }
      assertTransition(stored.state, "MERGING");
      const from = stored.state;
      stored.state = "MERGING";
      stored.revision += 1;
      stored.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: taskId,
        attempt_id: candidate.attempt_id,
        from_state: from,
        to_state: "MERGING",
        reason_code: "MERGE_REQUEST_ACCEPTED",
        actor_class: "CONTROLLER",
        actor_id: actorId,
        at: this.#now().toISOString(),
        correlation_id: correlationId,
        authoritative_revision: stored.revision,
        details: {
          pr_number: candidate.pull_request!.pr_number,
          expected_head_sha: candidate.integration_candidate!.commit_sha,
          remote_verification_report_hash:
            candidate.remote_verification_report!.report_hash,
        },
      });
      return structuredClone(stored);
    });
  }

  failMergeExternal(
    taskId: string,
    reasonCode: string,
    details: Record<string, unknown> = {},
  ): StoredTask {
    return this.#store.mutate((snapshot) => {
      const task = snapshot.tasks[taskId];
      if (!task) {
        throw new ControllerError(
          "TASK_NOT_FOUND",
          `Task ${taskId} was not found`,
        );
      }
      if (task.state !== "MERGING") {
        throw new ControllerError(
          "MERGE_FAILURE_STATE_INVALID",
          "Only MERGING tasks can be moved to EXTERNAL_BLOCKER by merge failure",
          { state: task.state },
        );
      }
      const attempt = Object.values(snapshot.attempts).find(
        (entry) =>
          entry.task_id === taskId &&
          entry.state === "CANDIDATE" &&
          entry.integration_candidate &&
          entry.pull_request &&
          entry.remote_verification_report?.status === "PASS",
      );
      assertTransition(task.state, "EXTERNAL_BLOCKER");
      const from = task.state;
      task.state = "EXTERNAL_BLOCKER";
      task.revision += 1;
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attempt?.attempt_id ?? null,
        from_state: from,
        to_state: "EXTERNAL_BLOCKER",
        reason_code: reasonCode,
        actor_class: "CONTROLLER",
        actor_id: "trusted-git-integrator",
        at: this.#now().toISOString(),
        correlation_id: attempt?.correlation_id ?? `merge:${taskId}`,
        authoritative_revision: task.revision,
        details,
      });
      return structuredClone(task);
    });
  }

  completeMerge(receiptInput: GitHubMergeReceipt): StoredTask {
    const receipt = verifyGitHubMergeReceipt(receiptInput);
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[receipt.attempt_id];
      if (!attempt) {
        throw new ControllerError(
          "ATTEMPT_NOT_FOUND",
          "Attempt " + receipt.attempt_id + " was not found",
        );
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) {
        throw new ControllerError("TASK_NOT_FOUND", "Merge task was not found");
      }
      if (attempt.merge_receipt) {
        if (attempt.merge_receipt.receipt_hash !== receipt.receipt_hash) {
          throw new ControllerError(
            "GITHUB_MERGE_RECEIPT_CONFLICT",
            "A different merge receipt is already bound to this attempt",
          );
        }
        return structuredClone(task);
      }
      if (task.state !== "MERGING" || attempt.state !== "CANDIDATE") {
        throw new ControllerError(
          "MERGE_COMPLETION_NOT_READY",
          "Merge completion requires MERGING task and exact candidate attempt",
          { taskState: task.state, attemptState: attempt.state },
        );
      }
      const integration = attempt.integration_candidate;
      const publication = attempt.pull_request;
      const remote = attempt.remote_verification_report;
      const passport = snapshot.passports[task.spec.repo_id]?.passport;
      if (!integration || !publication || !remote || !passport) {
        throw new ControllerError(
          "MERGE_EVIDENCE_NOT_READY",
          "Merge completion is missing deterministic integration/PR/remote/passport evidence",
        );
      }
      if (
        receipt.repo_id !== task.spec.repo_id ||
        receipt.task_id !== task.spec.task_id ||
        receipt.attempt_id !== attempt.attempt_id ||
        receipt.pr_number !== publication.pr_number ||
        receipt.integration_artifact_hash !== integration.artifact_hash ||
        receipt.remote_verification_report_hash !== remote.report_hash ||
        receipt.expected_head_sha !== integration.commit_sha ||
        receipt.merge_method !== passport.merge_method
      ) {
        throw new ControllerError(
          "GITHUB_MERGE_RECEIPT_BINDING_MISMATCH",
          "GitHub merge receipt is not bound to the exact verified integration/PR evidence",
        );
      }
      assertTransition(task.state, "POST_MERGE_VERIFY");
      const from = task.state;
      task.state = "POST_MERGE_VERIFY";
      task.revision += 1;
      attempt.merge_receipt = structuredClone(receipt);
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attempt.attempt_id,
        from_state: from,
        to_state: "POST_MERGE_VERIFY",
        reason_code: "REMOTE_MERGE_OBSERVED",
        actor_class: "CONTROLLER",
        actor_id: receipt.observer.build,
        at: receipt.merged_at,
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          pr_number: receipt.pr_number,
          merge_sha: receipt.merge_sha,
          observed_base_sha: receipt.observed_base_sha,
          base_head_matches_merge: receipt.base_head_matches_merge,
          merge_receipt_hash: receipt.receipt_hash,
        },
      });
      return structuredClone(task);
    });
  }

  completePostMergeVerification(
    reportInput: PostMergeVerificationReport,
  ): StoredTask {
    const report = verifyPostMergeVerificationReport(reportInput);
    if (report.status === "PENDING") {
      throw new ControllerError(
        "POST_MERGE_VERIFICATION_PENDING",
        "Post-merge verification is still waiting for required checks",
      );
    }
    return this.#store.mutate((snapshot) => {
      const attempt = snapshot.attempts[report.attempt_id];
      if (!attempt) {
        throw new ControllerError(
          "ATTEMPT_NOT_FOUND",
          "Attempt " + report.attempt_id + " was not found",
        );
      }
      const task = snapshot.tasks[attempt.task_id];
      if (!task) {
        throw new ControllerError(
          "TASK_NOT_FOUND",
          "Post-merge verification task was not found",
        );
      }
      if (attempt.post_merge_verification_report) {
        if (
          attempt.post_merge_verification_report.report_hash !==
          report.report_hash
        ) {
          throw new ControllerError(
            "POST_MERGE_VERIFICATION_REPORT_CONFLICT",
            "A different post-merge verification report is already bound to this attempt",
          );
        }
        return structuredClone(task);
      }
      if (task.state !== "POST_MERGE_VERIFY") {
        throw new ControllerError(
          "POST_MERGE_VERIFICATION_NOT_READY",
          "Post-merge verification requires POST_MERGE_VERIFY task state",
          { state: task.state },
        );
      }
      const receipt = attempt.merge_receipt;
      const passport = snapshot.passports[task.spec.repo_id]?.passport;
      if (!receipt || !passport) {
        throw new ControllerError(
          "POST_MERGE_EVIDENCE_MISSING",
          "Post-merge verification requires persisted merge receipt and Repo Passport",
        );
      }
      if (
        report.provider !== "github" ||
        report.repo_id !== task.spec.repo_id ||
        report.task_id !== task.spec.task_id ||
        report.attempt_id !== attempt.attempt_id ||
        report.merge_receipt_hash !== receipt.receipt_hash ||
        report.merge_sha !== receipt.merge_sha ||
        JSON.stringify([...report.required_checks].sort()) !==
          JSON.stringify([...passport.post_merge_checks].sort())
      ) {
        throw new ControllerError(
          "POST_MERGE_VERIFICATION_BINDING_MISMATCH",
          "Post-merge report is not bound to merge receipt and configured Repo Passport checks",
        );
      }
      const to: TaskState =
        report.status === "PASS"
          ? "DONE"
          : report.status === "QUALITY_FAILED"
            ? "QUALITY_FAILED"
            : "EXTERNAL_BLOCKER";
      assertTransition(task.state, to);
      const from = task.state;
      task.state = to;
      task.revision += 1;
      attempt.post_merge_verification_report = structuredClone(report);
      task.events.push({
        schema_version: "1.0",
        event_id: randomUUID(),
        task_id: task.spec.task_id,
        attempt_id: attempt.attempt_id,
        from_state: from,
        to_state: to,
        reason_code:
          report.status === "PASS"
            ? "POST_MERGE_GATES_PASSED"
            : "POST_MERGE_" + report.status,
        actor_class: "CONTROLLER",
        actor_id: report.observer.build,
        at: report.observed_at,
        correlation_id: attempt.correlation_id,
        authoritative_revision: task.revision,
        details: {
          merge_sha: report.merge_sha,
          post_merge_verification_report_hash: report.report_hash,
          required_checks: report.required_checks,
        },
      });
      return structuredClone(task);
    });
  }

  #event(
    taskId: string,
    attemptId: string | null,
    from: TaskState,
    to: TaskState,
    reasonCode: string,
    actorClass: TaskStateEvent["actor_class"],
    at: string,
  ): TaskStateEvent {
    assertTransition(from, to);
    return {
      schema_version: "1.0",
      event_id: randomUUID(),
      task_id: taskId,
      attempt_id: attemptId,
      from_state: from,
      to_state: to,
      reason_code: reasonCode,
      actor_class: actorClass,
      at,
      correlation_id: `bootstrap:${taskId}`,
    };
  }

  #validateLoadedState(): void {
    const snapshot = this.#store.snapshot;
    for (const entry of Object.values(snapshot.passports)) {
      this.#contracts.validate<RepoPassport>("repo-passport", entry.passport);
      const actual = sha256CanonicalJson(entry.passport);
      if (actual !== entry.sha256) {
        throw new ControllerError("STATE_CORRUPTION", `Repo Passport hash mismatch for ${entry.passport.repo_id}`);
      }
    }
    for (const machine of Object.values(snapshot.machines)) {
      this.#contracts.validate<MachineCapability>("machine-capability", machine);
    }
    for (const task of Object.values(snapshot.tasks)) {
      this.#contracts.validate<TaskSpec>("task-spec", task.spec);
    }
  }
}

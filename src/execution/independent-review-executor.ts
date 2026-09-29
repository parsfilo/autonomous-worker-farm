import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import type { EgressProfile, TaskSpec } from "../../contracts/types.js";
import { ControllerCore } from "../controller/controller.js";
import {
  finalizeIndependentReviewReport,
  parseOpenCodeReviewOutput,
  sha256Text,
} from "../evidence/independent-review.js";
import { OpenCodeAdapter } from "../harness/opencode/adapter.js";
import type { ClaimedAttemptBroker, ClaimedAttemptPreparer } from "./claimed-attempt-executor.js";
import { sha256Bytes } from "../evidence/candidate.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";
import { materializeGitHubPublicRepo } from "../repo/github-public.js";
import { prepareMaterializedRepoForWorker } from "../repo/workspace-access.js";
import { SandboxBrokerClient } from "../sandbox/broker-client.js";
import { buildSandboxRequest } from "../sandbox/request-builder.js";
import { computeSandboxRequestBindingHash } from "../sandbox/request-binding.js";
import type { StoredRepoSource } from "../store/file-store.js";

const execFileAsync = promisify(execFile);
const DEFAULT_POLL_MS = 1000;

interface RuntimeImageLock {
  worker: {
    reference: string;
    digest: string;
    toolchain: { opencode: string };
  };
}

export interface ReviewCandidatePreparationInput {
  source: StoredRepoSource;
  task: TaskSpec;
  repoPath: string;
  patchPath: string;
  patchSha256: string;
  changedFiles: string[];
}

export type ReviewCandidatePreparer = (
  input: ReviewCandidatePreparationInput,
) => Promise<void>;

export interface IndependentReviewExecutorOptions {
  core: ControllerCore;
  broker?: ClaimedAttemptBroker;
  egressProfilePath: string;
  runtimeImageLockPath: string;
  pollIntervalMs?: number;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  materialize?: typeof materializeGitHubPublicRepo;
  prepareCandidate?: ReviewCandidatePreparer;
  adapter?: ClaimedAttemptPreparer;
}

async function loadJson<T>(path: string, label: string): Promise<T> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch (error) {
    throw new ControllerError("REVIEW_CONFIG_LOAD_FAILED", "Could not load " + label, {
      path,
      cause: error instanceof Error ? error.message : String(error),
    });
  }
}

async function git(args: string[], cwd: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/git", args, {
      cwd,
      timeout: 60_000,
      maxBuffer: 16 * 1024 * 1024,
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C.UTF-8",
        HOME: "/nonexistent",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_TERMINAL_PROMPT: "0",
      },
    });
    return stdout;
  } catch (error) {
    const value = error as { stderr?: string; message?: string };
    throw new ControllerError("REVIEW_PATCH_APPLY_FAILED", "Could not materialize exact candidate patch", {
      argv: args,
      stderr: value.stderr?.slice(-4096) ?? "",
      cause: value.message ?? String(error),
    });
  }
}

async function defaultPrepareCandidate(
  materialize: typeof materializeGitHubPublicRepo,
  input: ReviewCandidatePreparationInput,
): Promise<void> {
  await materialize(input.source, input.task, input.repoPath);
  await prepareMaterializedRepoForWorker(input.repoPath);
  const patchBytes = await readFile(input.patchPath);
  if (sha256Bytes(patchBytes) !== input.patchSha256) {
    throw new ControllerError("REVIEW_PATCH_HASH_MISMATCH", "Candidate patch artifact hash changed");
  }
  await git(["apply", "--check", "--binary", input.patchPath], input.repoPath);
  await git(["apply", "--binary", "--whitespace=nowarn", input.patchPath], input.repoPath);

  const changed = (await git(["diff", "--name-only", "-z", "HEAD", "--"], input.repoPath))
    .split("\0")
    .filter(Boolean)
    .sort();
  const expectedChanged = [...input.changedFiles].sort();
  if (JSON.stringify(changed) !== JSON.stringify(expectedChanged)) {
    throw new ControllerError(
      "REVIEW_CANDIDATE_MATERIALIZATION_MISMATCH",
      "Applied candidate file set drifted",
    );
  }

  // Candidate patches may introduce files after the initial materialization.
  // Re-normalize modes and reject symlink/special-file additions before the
  // read-only reviewer sandbox sees the candidate.
  await prepareMaterializedRepoForWorker(input.repoPath);
}

export function buildIndependentReviewTask(source: TaskSpec, sourceAttemptId: string): TaskSpec {
  return {
    ...structuredClone(source),
    archetype: "independent-reviewer",
    objective:
      "Independently review the candidate currently applied in repo/. The Controller has already cryptographically bound the exact candidate; do not attempt to recompute or challenge candidate/patch hashes. Focus only on correctness, security, policy violations, regressions, and unmet acceptance criteria visible in the repository. " +
      "Inspect only files under repo/. Never access /tmp, /run outside the provided workspace, home directories, or any other external path. " +
      "Do not modify any file. Return exactly one JSON object with keys verdict, findings, summary. " +
      'verdict must be "PASS" or "BLOCK". findings must be an array of objects with exactly severity, code, summary, path, line. ' +
      'severity must be "BLOCKING" or "NON_BLOCKING". PASS requires zero BLOCKING findings; BLOCK requires at least one BLOCKING finding.',
    acceptance_criteria: [
      "Repository files remain unchanged by the reviewer.",
      "Output is one strict JSON review object and no prose.",
    ],
    read_scope: ["**"],
    write_scope: [],
    model_requirements: {
      ...source.model_requirements,
      class: "review",
      privacy_class: "public",
      provider_diversity_from_attempt_id: sourceAttemptId,
    },
    evidence_requirements: ["sandbox_attestation"],
    review_policy: {
      independent_review: false,
      require_provider_diversity: false,
      human_approval_required: source.review_policy.human_approval_required ?? false,
    },
  };
}

export class IndependentReviewExecutor {
  readonly #core: ControllerCore;
  readonly #broker: ClaimedAttemptBroker;
  readonly #egressProfilePath: string;
  readonly #runtimeImageLockPath: string;
  readonly #pollIntervalMs: number;
  readonly #now: () => Date;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #materialize: typeof materializeGitHubPublicRepo;
  readonly #prepareCandidate: ReviewCandidatePreparer;
  readonly #adapter: ClaimedAttemptPreparer;

  constructor(options: IndependentReviewExecutorOptions) {
    this.#core = options.core;
    this.#broker = options.broker ?? new SandboxBrokerClient();
    this.#egressProfilePath = options.egressProfilePath;
    this.#runtimeImageLockPath = options.runtimeImageLockPath;
    this.#pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_MS;
    this.#now = options.now ?? (() => new Date());
    this.#sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.#materialize = options.materialize ?? materializeGitHubPublicRepo;
    this.#prepareCandidate = options.prepareCandidate ?? ((input) => defaultPrepareCandidate(this.#materialize, input));
    this.#adapter = options.adapter ?? new OpenCodeAdapter();
  }

  async execute(reviewId: string) {
    const review = this.#core.getReview(reviewId);
    const task = this.#core.getTask(review.task_id).spec;
    const sourceAttempt = this.#core.getAttempt(review.source_attempt_id);
    const source = this.#core.getRepoSource(task.repo_id);
    const { passport } = this.#core.getPassport(task.repo_id);

    if (review.state !== "LEASED" || !review.machine_id || !review.model) {
      throw new ControllerError("REVIEW_STATE_INVALID", "Independent review must be LEASED before execution");
    }
    if (!sourceAttempt.result_manifest || !sourceAttempt.patch_path) {
      throw new ControllerError("REVIEW_SOURCE_EVIDENCE_MISSING", "Source candidate evidence is missing");
    }
    if (
      sourceAttempt.result_manifest.candidate_hash !== review.candidate_hash ||
      sourceAttempt.result_manifest.patch_sha256 !== review.patch_sha256
    ) {
      throw new ControllerError("REVIEW_SOURCE_DRIFT", "Source candidate binding changed before review");
    }

    const imageLock = await loadJson<RuntimeImageLock>(this.#runtimeImageLockPath, "runtime image lock");
    const egressProfile = await loadJson<EgressProfile>(this.#egressProfilePath, "OpenCode free egress profile");
    const health = await this.#broker.health();
    if (
      health.status !== "ready" ||
      !health.runtime_ready ||
      !health.workspace_manager_ready ||
      health.machine_id !== review.machine_id
    ) {
      this.#core.failReview(reviewId, "BROKER_NOT_READY");
      throw new ControllerError("BROKER_NOT_READY", "Review broker is not ready");
    }

    let lease = null as Awaited<ReturnType<ClaimedAttemptBroker["issueWorkspaceLease"]>> | null;
    let requestId: string | null = null;
    let provisioned = false;

    try {
      lease = await this.#broker.issueWorkspaceLease({
        attempt_id: reviewId,
        machine_id: review.machine_id,
        ttl_seconds: Math.min(task.lease_ttl_seconds, 3600),
      });
      await this.#prepareCandidate({
        source,
        task,
        repoPath: lease.paths.repo,
        patchPath: sourceAttempt.patch_path,
        patchSha256: review.patch_sha256,
        changedFiles: sourceAttempt.result_manifest.changed_files,
      });

      requestId = "request-" + randomUUID();

      const reviewSpec = buildIndependentReviewTask(task, sourceAttempt.attempt_id);
      const built = buildSandboxRequest({
        requestId,
        attemptId: reviewId,
        task: reviewSpec,
        machineId: review.machine_id,
        tier: "T1",
        lease,
        image: {
          reference: imageLock.worker.reference,
          digest: imageLock.worker.digest,
        },
        resources: {
          cpu: 1,
          memory_bytes: 1024 ** 3,
          pids: 256,
          tmpfs_bytes: 256 * 1024 ** 2,
          timeout_seconds: task.timeout_seconds,
        },
        policyHash: sha256CanonicalJson({
          executor: "independent-review-v1",
          task_id: task.task_id,
          source_attempt_id: sourceAttempt.attempt_id,
          candidate_hash: review.candidate_hash,
          reviewer_model: review.model.model,
          workspace_read_only: true,
        }),
        network: {
          profile: "brokered",
          egressProfile,
          routeId: "opencode-free",
          model: review.model.model,
        },
        workspaceReadOnly: true,
        authorizationTtlSeconds: Math.min(task.timeout_seconds, 300),
        now: this.#now(),
      });
      if (!built.proxyURL || built.selectedModel !== review.model.model || !built.request.workspace.read_only) {
        throw new ControllerError("REVIEW_SANDBOX_BINDING_MISMATCH", "Review sandbox lost model/proxy/read-only binding");
      }
      const sandboxRequestHash = computeSandboxRequestBindingHash(built.request);
      this.#core.beginReviewProvisioning(
        reviewId,
        requestId,
        lease.lease_id,
        lease.paths.run_root,
        sandboxRequestHash,
        true,
      );

      await this.#adapter.prepare({
        task: reviewSpec,
        passport,
        runRoot: lease.paths.run_root,
        policy: {
          model: review.model.model,
          proxyURL: built.proxyURL,
          shellAllowlist: [],
          approvedSkillIds: [],
          readOnlyReviewMode: true,
        },
      });

      const attestation = await this.#broker.provision(built.request);
      provisioned = true;
      const running = this.#core.markReviewRunning(reviewId, attestation, attestation.started_at);

      const deadline = this.#now().getTime() + task.timeout_seconds * 1000;
      for (;;) {
        if (this.#now().getTime() >= deadline) {
          await this.#broker.terminate(requestId, reviewId);
          provisioned = false;
          this.#core.failReview(reviewId, "REVIEW_TIMEOUT");
          throw new ControllerError("REVIEW_TIMEOUT", "Independent review exceeded task timeout");
        }
        const status = await this.#broker.status(requestId, reviewId);
        if (status.state === "NOT_FOUND") {
          this.#core.failReview(reviewId, "REVIEW_CONTAINER_LOST");
          throw new ControllerError("REVIEW_CONTAINER_LOST", "Review worker container disappeared");
        }
        if (status.state === "RUNNING") {
          await this.#sleep(this.#pollIntervalMs);
          continue;
        }
        if (status.exit_code !== 0) {
          this.#core.failReview(reviewId, "REVIEW_WORKER_EXIT_NONZERO", status.exit_code);
          throw new ControllerError("REVIEW_WORKER_EXIT_NONZERO", "Review worker exited unsuccessfully", {
            exitCode: status.exit_code,
            stderr: status.stderr_tail.slice(-4096),
          });
        }

        const parsed = parseOpenCodeReviewOutput(status.stdout_tail);
        const report = finalizeIndependentReviewReport({
          schema_version: "1.0",
          review_id: reviewId,
          task_id: task.task_id,
          source_attempt_id: sourceAttempt.attempt_id,
          review_attempt_id: reviewId,
          candidate_hash: review.candidate_hash,
          patch_sha256: review.patch_sha256,
          base_sha: task.base_sha,
          verdict: parsed.verdict,
          findings: parsed.findings,
          summary: parsed.summary,
          reviewer: {
            machine_id: review.machine_id,
            provider: "opencode",
            model: review.model.model,
            harness_adapter: "opencode",
            harness_version: imageLock.worker.toolchain.opencode,
          },
          sandbox: {
            tier: "T1",
            request_hash: attestation.request_hash,
            image_digest: attestation.image_digest,
            network_profile: "brokered",
            workspace_read_only: true,
          },
          started_at: running.started_at ?? attestation.started_at,
          ended_at: status.observed_at,
          raw_output_sha256: sha256Text(status.stdout_tail),
        });
        const completed = this.#core.completeReview(reviewId, report);
        return { review: completed, report, brokerHealth: health };
      }
    } catch (error) {
      const current = this.#core.getReview(reviewId);
      if (["LEASED", "PROVISIONING", "RUNNING"].includes(current.state)) {
        this.#core.failReview(
          reviewId,
          error instanceof ControllerError ? error.code : "REVIEW_EXECUTOR_FAILED",
        );
      }
      throw error;
    } finally {
      if (requestId && provisioned) {
        try {
          await this.#broker.terminate(requestId, reviewId);
        } catch {
          // lease release remains the final cleanup authority
        }
      }
      if (lease) {
        await this.#broker.releaseWorkspaceLease(lease);
      }
    }
  }
}

import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  writeFile,
} from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";
import type {
  EgressProfile,
  GateEvidence,
  ResultManifest,
  SandboxWorkspaceLease,
} from "../../contracts/types.js";
import { ControllerCore } from "../controller/controller.js";
import { buildCandidateDescriptor, computeCandidateHash, sha256Bytes } from "../evidence/candidate.js";
import { verifyWorkerManifest } from "../evidence/verify-worker-manifest.js";
import { OpenCodeAdapter, OPENCODE_FIXED_RUN_ARGV } from "../harness/opencode/adapter.js";
import type { HarnessPrepareContext, PreparedRun } from "../harness/adapter.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";
import { materializeGitHubPublicRepo } from "../repo/github-public.js";
import { prepareMaterializedRepoForWorker } from "../repo/workspace-access.js";
import { WORKER_UID } from "../sandbox/docker-spec.js";
import {
  SandboxBrokerClient,
  type AttemptStatusResult,
  type SandboxBrokerHealth,
  type TerminateResult,
  type WorkspaceLeaseReleaseResult,
  type WorkspaceLeaseRequest,
} from "../sandbox/broker-client.js";
import { buildSandboxRequest } from "../sandbox/request-builder.js";
import {
  buildValidationPlanFromQualityProfile,
  loadTrustedQualityProfile,
} from "../quality/profile.js";
import type { StoredAttempt } from "../store/file-store.js";

const execFileAsync = promisify(execFile);
const MAX_PATCH_BYTES = 32 * 1024 * 1024;
const DEFAULT_POLL_MS = 1000;

interface RuntimeImageLock {
  worker: {
    reference: string;
    tag: string;
    digest: string;
    toolchain: {
      opencode: string;
    };
  };
}

export interface CandidateEvidence {
  headSha: string;
  changedFiles: string[];
  patchBytes: Uint8Array;
}

export interface ClaimedAttemptPreparer {
  prepare(context: HarnessPrepareContext): Promise<PreparedRun>;
}

export interface ClaimedAttemptBroker {
  health(): Promise<SandboxBrokerHealth>;
  issueWorkspaceLease(input: WorkspaceLeaseRequest): Promise<SandboxWorkspaceLease>;
  releaseWorkspaceLease(lease: SandboxWorkspaceLease): Promise<WorkspaceLeaseReleaseResult>;
  provision(input: Parameters<SandboxBrokerClient["provision"]>[0]): ReturnType<SandboxBrokerClient["provision"]>;
  status(requestId: string, attemptId: string): Promise<AttemptStatusResult>;
  terminate(requestId: string, attemptId: string): Promise<TerminateResult>;
}

export interface ClaimedAttemptExecutorOptions {
  core: ControllerCore;
  broker?: ClaimedAttemptBroker;
  egressProfilePath: string;
  runtimeImageLockPath: string;
  candidateArtifactRoot: string;
  qualityProfileRoot?: string;
  validationRoot?: string;
  pollIntervalMs?: number;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
  materialize?: typeof materializeGitHubPublicRepo;
  collectCandidate?: (repoPath: string, expectedBaseSha: string) => Promise<CandidateEvidence>;
  adapter?: ClaimedAttemptPreparer;
  prepareRepoAccess?: typeof prepareMaterializedRepoForWorker;
}

export interface ClaimedAttemptExecutionResult {
  attempt: StoredAttempt;
  manifest: ResultManifest;
  patchPath: string;
  brokerHealth: SandboxBrokerHealth;
}

function missingGate(): GateEvidence {
  return {
    status: "MISSING",
    exit_code: null,
    report_sha256: null,
    report_uri: null,
    details: {
      reason: "not collected by Phase-1 claimed-attempt executor",
    },
  };
}

function safeDurationMs(startedAt: string, endedAt: string): number {
  const start = Date.parse(startedAt);
  const end = Date.parse(endedAt);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return 0;
  return Math.round(end - start);
}

function isRateLimitFailure(status: AttemptStatusResult): boolean {
  const text = (status.stdout_tail + "\n" + status.stderr_tail).toLowerCase();
  return (
    text.includes("429") ||
    text.includes("rate limit") ||
    text.includes("rate-limit") ||
    text.includes("too many requests") ||
    text.includes("quota exceeded")
  );
}

async function runGit(args: string[], cwd: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/git", args, {
      cwd,
      timeout: 60_000,
      maxBuffer: MAX_PATCH_BYTES + 1024 * 1024,
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C.UTF-8",
        HOME: "/nonexistent",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_TERMINAL_PROMPT: "0",
        GCM_INTERACTIVE: "Never",
      },
    });
    return Buffer.from(stdout).toString("utf8");
  } catch (error) {
    const value = error as { stderr?: Buffer | string; message?: string };
    throw new ControllerError("CANDIDATE_GIT_FAILED", "Candidate Git command failed", {
      argv: args,
      stderr: value.stderr ? Buffer.from(value.stderr).toString("utf8").slice(-4096) : "",
      cause: value.message ?? String(error),
    });
  }
}

export async function collectGitCandidate(
  repoPath: string,
  expectedBaseSha: string,
): Promise<CandidateEvidence> {
  const headSha = (await runGit(["rev-parse", "--verify", "HEAD^{commit}"], repoPath))
    .trim()
    .toLowerCase();
  if (headSha !== expectedBaseSha) {
    throw new ControllerError("BASE_DRIFT", "Worker changed repository HEAD", {
      expected: expectedBaseSha,
      actual: headSha,
    });
  }

  const remotes = (await runGit(["remote"], repoPath)).trim();
  if (remotes !== "") {
    throw new ControllerError(
      "REMOTE_CREDENTIAL_BOUNDARY_BROKEN",
      "Materialized worker repository unexpectedly retained a Git remote",
      { remotes },
    );
  }

  // Intent-to-add lets Git include untracked files in the binary patch without
  // committing or changing working-tree content.
  await runGit(["add", "-N", "-A", "--", "."], repoPath);
  const changedRaw = await runGit(
    ["diff", "--name-only", "-z", "--no-ext-diff", "HEAD", "--"],
    repoPath,
  );
  const changedFiles = changedRaw
    .split("\0")
    .filter(Boolean)
    .map((value) => value.replaceAll("\\", "/"));

  const patchText = await runGit(
    ["diff", "--binary", "--no-ext-diff", "--full-index", "HEAD", "--"],
    repoPath,
  );
  const patchBytes = Buffer.from(patchText, "utf8");
  if (patchBytes.byteLength > MAX_PATCH_BYTES) {
    throw new ControllerError("CANDIDATE_PATCH_TOO_LARGE", "Candidate patch exceeds Phase-1 limit", {
      bytes: patchBytes.byteLength,
      maxBytes: MAX_PATCH_BYTES,
    });
  }
  return { headSha, changedFiles, patchBytes };
}

export function exactShellAllowlist(
  buildCommands: string[][],
  testCommands: string[][],
): string[] {
  const values: string[] = [];
  for (const argv of [...buildCommands, ...testCommands]) {
    if (argv.length === 0) continue;
    values.push(argv.join(" "));

    const repoCwd = argv.map((arg) => {
      const normalized = arg.replaceAll("\\", "/");
      if (normalized.startsWith("repo/")) return normalized.slice("repo/".length);
      if (normalized.startsWith("./repo/")) return normalized.slice("./repo/".length);
      return arg;
    });
    if (repoCwd.some((arg, index) => arg !== argv[index])) {
      values.push(repoCwd.join(" "));
    }
  }
  return [...new Set(values.filter(Boolean))];
}

async function loadJson<T>(path: string, label: string): Promise<T> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as T;
  } catch (error) {
    throw new ControllerError("EXECUTOR_CONFIG_LOAD_FAILED", "Could not load " + label, {
      path,
      cause: error instanceof Error ? error.message : String(error),
    });
  }
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
  await mkdir(root, { recursive: true, mode: 0o700 });
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new ControllerError(
      "CANDIDATE_ARTIFACT_ROOT_INVALID",
      "Candidate artifact root must be a real directory",
    );
  }

  const attemptDir = join(root, attemptId);
  try {
    await mkdir(attemptDir, { mode: 0o700 });
  } catch (error) {
    const code =
      error && typeof error === "object" && "code" in error
        ? String((error as { code?: unknown }).code ?? "")
        : "";
    if (code === "EEXIST") {
      throw new ControllerError(
        "CANDIDATE_ARTIFACT_EXISTS",
        "Candidate artifact directory already exists; refusing to overwrite evidence",
        { attemptId },
      );
    }
    throw error;
  }
  const patchPath = join(attemptDir, "candidate.patch");
  await writeFile(patchPath, patchBytes, { mode: 0o600 });
  await chmod(patchPath, 0o600);
  return patchPath;
}

export class ClaimedAttemptExecutor {
  readonly #core: ControllerCore;
  readonly #broker: ClaimedAttemptBroker;
  readonly #egressProfilePath: string;
  readonly #runtimeImageLockPath: string;
  readonly #candidateArtifactRoot: string;
  readonly #qualityProfileRoot: string | null;
  readonly #validationRoot: string | null;
  readonly #pollIntervalMs: number;
  readonly #now: () => Date;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #materialize: typeof materializeGitHubPublicRepo;
  readonly #collectCandidate: (
    repoPath: string,
    expectedBaseSha: string,
  ) => Promise<CandidateEvidence>;
  readonly #adapter: ClaimedAttemptPreparer;
  readonly #prepareRepoAccess: typeof prepareMaterializedRepoForWorker;

  constructor(options: ClaimedAttemptExecutorOptions) {
    this.#core = options.core;
    this.#broker = options.broker ?? new SandboxBrokerClient();
    this.#egressProfilePath = options.egressProfilePath;
    this.#runtimeImageLockPath = options.runtimeImageLockPath;
    this.#candidateArtifactRoot = options.candidateArtifactRoot;
    this.#qualityProfileRoot = options.qualityProfileRoot ? resolve(options.qualityProfileRoot) : null;
    this.#validationRoot = options.validationRoot ? resolve(options.validationRoot) : null;
    if ((this.#qualityProfileRoot === null) !== (this.#validationRoot === null)) {
      throw new ControllerError(
        "EXECUTOR_CONFIG_INVALID",
        "qualityProfileRoot and validationRoot must be configured together",
      );
    }
    this.#pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_MS;
    this.#now = options.now ?? (() => new Date());
    this.#sleep =
      options.sleep ??
      (async (ms) => {
        await new Promise((resolve) => setTimeout(resolve, ms));
      });
    this.#materialize = options.materialize ?? materializeGitHubPublicRepo;
    this.#collectCandidate = options.collectCandidate ?? collectGitCandidate;
    this.#adapter = options.adapter ?? new OpenCodeAdapter();
    this.#prepareRepoAccess =
      options.prepareRepoAccess ?? prepareMaterializedRepoForWorker;

    if (!Number.isInteger(this.#pollIntervalMs) || this.#pollIntervalMs < 10) {
      throw new ControllerError(
        "EXECUTOR_CONFIG_INVALID",
        "pollIntervalMs must be an integer of at least 10ms",
      );
    }
  }

  async execute(attemptId: string): Promise<ClaimedAttemptExecutionResult> {
    const attempt = this.#core.getAttempt(attemptId);
    const taskRecord = this.#core.getTask(attempt.task_id);
    const task = taskRecord.spec;
    const { passport } = this.#core.getPassport(task.repo_id);
    const source = this.#core.getRepoSource(task.repo_id);

    if (attempt.state !== "LEASED" || taskRecord.state !== "LEASED") {
      throw new ControllerError(
        "ATTEMPT_STATE_INVALID",
        "Claimed-attempt executor requires a LEASED attempt",
      );
    }
    if (
      task.archetype === "independent-reviewer" ||
      task.write_scope.length === 0
    ) {
      throw new ControllerError(
        "EXECUTOR_READ_ONLY_FLOW_NOT_READY",
        "Read-only/reviewer execution uses a separate evidence flow and is not candidate-producing",
      );
    }
    if (attempt.harness_adapter !== "opencode" || attempt.model.provider !== "opencode") {
      throw new ControllerError(
        "EXECUTOR_ROUTE_INVALID",
        "Phase-1 claimed-attempt executor only supports OpenCode free attempts",
      );
    }

    const imageLock = await loadJson<RuntimeImageLock>(
      this.#runtimeImageLockPath,
      "runtime image lock",
    );
    if (
      !imageLock.worker ||
      typeof imageLock.worker.reference !== "string" ||
      typeof imageLock.worker.digest !== "string" ||
      !/^sha256:[0-9a-f]{64}$/.test(imageLock.worker.digest) ||
      typeof imageLock.worker.toolchain?.opencode !== "string"
    ) {
      throw new ControllerError(
        "EXECUTOR_IMAGE_LOCK_INVALID",
        "Worker runtime image lock is invalid",
      );
    }
    const egressProfile = await loadJson<EgressProfile>(
      this.#egressProfilePath,
      "OpenCode free egress profile",
    );

    const health = await this.#broker.health();
    if (
      health.status !== "ready" ||
      !health.runtime_ready ||
      !health.workspace_manager_ready ||
      health.machine_id !== attempt.machine_id
    ) {
      this.#core.failAttempt(
        attemptId,
        "MACHINE_OFFLINE",
        "BROKER_NOT_READY",
        null,
        { health },
      );
      throw new ControllerError(
        "BROKER_NOT_READY",
        "Claimed machine broker is not ready for execution",
        { health },
      );
    }

    let lease: SandboxWorkspaceLease | null = null;
    let requestId: string | null = null;
    let provisioned = false;
    let promoted = false;

    try {
      try {
        lease = await this.#broker.issueWorkspaceLease({
          attempt_id: attemptId,
          machine_id: attempt.machine_id,
          ttl_seconds: Math.min(task.lease_ttl_seconds, 3600),
        });
      } catch (error) {
        this.#core.failAttempt(
          attemptId,
          "LOST",
          "WORKSPACE_LEASE_FAILED",
          null,
          { cause: error instanceof Error ? error.message : String(error) },
        );
        throw error;
      }

      try {
        await this.#materialize(source, task, lease.paths.repo);
        await this.#prepareRepoAccess(lease.paths.repo);
      } catch (error) {
        const code = error instanceof ControllerError ? error.code : "";
        this.#core.failAttempt(
          attemptId,
          code === "BASE_DRIFT" ? "BASE_DRIFT" : "LOST",
          code === "BASE_DRIFT" ? "BASE_DRIFT_DETECTED" : "REPO_MATERIALIZATION_FAILED",
          null,
          { cause: error instanceof Error ? error.message : String(error) },
        );
        throw error;
      }

      requestId = "request-" + randomUUID();
      this.#core.beginAttemptProvisioning(
        attemptId,
        requestId,
        lease.lease_id,
        lease.paths.run_root,
      );

      const policyHash = sha256CanonicalJson({
        executor: "claimed-attempt-v1",
        task_id: task.task_id,
        task_revision: task.task_revision ?? 1,
        repo_passport_hash: task.repo_passport_hash,
        model_provider: attempt.model.provider,
        model: attempt.model.model,
        network_profile: task.network_profile,
        route_id: "opencode-free",
        worker_image_digest: imageLock.worker.digest,
      });

      const built = buildSandboxRequest({
        requestId,
        attemptId,
        task,
        machineId: attempt.machine_id,
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
        policyHash,
        network: {
          profile: "brokered",
          egressProfile,
          routeId: "opencode-free",
          model: attempt.model.model,
        },
        authorizationTtlSeconds: Math.min(task.timeout_seconds, 300),
        now: this.#now(),
      });

      if (built.selectedModel !== attempt.model.model || !built.proxyURL) {
        throw new ControllerError(
          "EXECUTOR_MODEL_BINDING_MISMATCH",
          "Sandbox request did not preserve the claimed model/proxy binding",
        );
      }

      await this.#adapter.prepare({
        task,
        passport,
        runRoot: lease.paths.run_root,
        policy: {
          model: attempt.model.model,
          proxyURL: built.proxyURL,
          shellAllowlist: exactShellAllowlist(
            passport.allowed_build_commands,
            passport.allowed_test_commands,
          ),
          approvedSkillIds: task.approved_skills.map((skill) => skill.id),
        },
      });

      const attestation = await this.#broker.provision(built.request);
      provisioned = true;
      const running = this.#core.markAttemptRunning(
        attemptId,
        attestation,
        attestation.started_at,
      );

      const deadline = this.#now().getTime() + task.timeout_seconds * 1000;
      let status: AttemptStatusResult;
      let lastStatus: AttemptStatusResult | null = null;
      for (;;) {
        if (this.#now().getTime() >= deadline) {
          try {
            lastStatus = await this.#broker.status(requestId, attemptId);
          } catch {
            // Preserve the last successfully observed status if the broker
            // cannot provide one more sample at the timeout boundary.
          }
          const telemetry = {
            timeout_seconds: task.timeout_seconds,
            stdout_tail: lastStatus?.stdout_tail.slice(-4096) ?? "",
            stderr_tail: lastStatus?.stderr_tail.slice(-4096) ?? "",
            last_observed_state: lastStatus?.state ?? null,
          };
          await this.#broker.terminate(requestId, attemptId);
          provisioned = false;
          this.#core.failAttempt(
            attemptId,
            "HARNESS_FAILED",
            "WORKER_TIMEOUT",
            null,
            telemetry,
          );
          throw new ControllerError(
            "WORKER_TIMEOUT",
            "Worker exceeded task timeout and was terminated",
            telemetry,
          );
        }

        status = await this.#broker.status(requestId, attemptId);
        lastStatus = status;
        if (status.state === "EXITED") break;
        if (status.state === "NOT_FOUND") {
          this.#core.failAttempt(
            attemptId,
            "LOST",
            "WORKER_CONTAINER_LOST",
            null,
          );
          throw new ControllerError(
            "WORKER_CONTAINER_LOST",
            "Broker could no longer find the running worker container",
          );
        }
        await this.#sleep(this.#pollIntervalMs);
      }

      if (status.exit_code !== 0) {
        const rateLimited = isRateLimitFailure(status);
        this.#core.failAttempt(
          attemptId,
          rateLimited ? "MODEL_RATE_LIMITED" : "HARNESS_FAILED",
          rateLimited ? "MODEL_RATE_LIMITED" : "WORKER_EXIT_NONZERO",
          status.exit_code,
          {
            stdout_tail: status.stdout_tail.slice(-4096),
            stderr_tail: status.stderr_tail.slice(-4096),
          },
        );
        throw new ControllerError(
          rateLimited ? "MODEL_RATE_LIMITED" : "WORKER_EXIT_NONZERO",
          "Worker exited unsuccessfully",
          {
            exitCode: status.exit_code,
            stdout_tail: status.stdout_tail.slice(-4096),
            stderr_tail: status.stderr_tail.slice(-4096),
          },
        );
      }

      await this.#prepareRepoAccess(lease.paths.repo, {
        additionalAllowedUids: [WORKER_UID],
      });
      const candidate = await this.#collectCandidate(lease.paths.repo, task.base_sha);
      if (candidate.changedFiles.length === 0 || candidate.patchBytes.byteLength === 0) {
        const telemetry = {
          stdout_tail: status.stdout_tail.slice(-4096),
          stderr_tail: status.stderr_tail.slice(-4096),
        };
        this.#core.failAttempt(
          attemptId,
          "HARNESS_FAILED",
          "EMPTY_WORKER_CHANGE",
          0,
          telemetry,
        );
        throw new ControllerError(
          "EMPTY_WORKER_CHANGE",
          "Successful worker produced no candidate changes",
          telemetry,
        );
      }

      const patchPath = await persistPatch(
        this.#candidateArtifactRoot,
        attemptId,
        candidate.patchBytes,
      );
      const patchSha = sha256Bytes(candidate.patchBytes);
      const endedAt = status.observed_at;
      const startedAt = running.started_at ?? attestation.started_at;
      const manifest: ResultManifest = {
        schema_version: "1.0",
        task_id: task.task_id,
        attempt_id: attemptId,
        attempt_no: attempt.attempt_no,
        base_sha: task.base_sha,
        repo_passport_hash: task.repo_passport_hash,
        context_snapshot_hash: task.context_snapshot_hash,
        machine: {
          machine_id: attempt.machine_id,
        },
        sandbox: {
          tier: attestation.tier,
          attested: true,
          landlock_abi: attestation.sandbox.landlock_abi,
          container_runtime: attestation.sandbox.container_runtime,
          container_image_digest: attestation.image_digest,
        },
        harness: {
          adapter: "opencode",
          version: imageLock.worker.toolchain.opencode,
          digest: null,
          session_id: null,
        },
        model: {
          provider: attempt.model.provider,
          model: attempt.model.model,
          request_ids: [],
        },
        approved_skills: task.approved_skills,
        tool_versions: {
          opencode: imageLock.worker.toolchain.opencode,
        },
        started_at: startedAt,
        ended_at: endedAt,
        status: "SUCCEEDED",
        changed_files: candidate.changedFiles,
        patch_sha256: patchSha,
        candidate_hash: "0".repeat(64),
        candidate_commit_sha: null,
        commands: [
          {
            argv: [...OPENCODE_FIXED_RUN_ARGV],
            cwd: "/run",
            exit_code: 0,
            duration_ms: safeDurationMs(startedAt, endedAt),
          },
        ],
        checks: {
          format: missingGate(),
          lint: missingGate(),
          typecheck: missingGate(),
          build: missingGate(),
          secret_scan: missingGate(),
        },
        tests: [],
        lsp_diagnostics: [],
        quality: {
          semgrep: missingGate(),
          codacy: missingGate(),
          sonar: missingGate(),
        },
        policy_events: [],
        network_events: [],
        artifacts: [
          {
            name: "candidate.patch",
            uri: null,
            sha256: patchSha,
            media_type: "text/x-diff",
          },
        ],
        summary:
          "Brokered OpenCode free worker exited successfully; Controller captured an exact Git patch. Optional quality gates were not collected by this Phase-1 executor.",
      };
      manifest.candidate_hash = computeCandidateHash(buildCandidateDescriptor(task, manifest));
      verifyWorkerManifest(task, passport, manifest, candidate.patchBytes, {
        enforceRequiredQuality: this.#qualityProfileRoot === null,
      });

      let nextAttempt: StoredAttempt;
      if (this.#qualityProfileRoot && this.#validationRoot) {
        const profile = loadTrustedQualityProfile(this.#qualityProfileRoot, task.quality_profile);
        const plan = buildValidationPlanFromQualityProfile({
          task,
          passport,
          candidateHash: manifest.candidate_hash,
          validationWorkspace: join(this.#validationRoot, attemptId, "repo"),
          profile,
        });
        nextAttempt = this.#core.beginLocalVerification(attemptId, manifest, patchPath, plan);
      } else {
        nextAttempt = this.#core.promoteAttemptCandidate(attemptId, manifest, patchPath);
      }
      promoted = true;
      return {
        attempt: nextAttempt,
        manifest,
        patchPath,
        brokerHealth: health,
      };
    } catch (error) {
      const current = this.#core.getAttempt(attemptId);
      if (
        current.state === "PROVISIONING" ||
        current.state === "RUNNING" ||
        current.state === "EVIDENCE_COLLECT" ||
        current.state === "LOCAL_VERIFY"
      ) {
        const code = error instanceof ControllerError ? error.code : "EXECUTOR_FAILED";
        const policyViolation =
          code === "REMOTE_CREDENTIAL_BOUNDARY_BROKEN" ||
          code === "RESULT_MANIFEST_MISMATCH" ||
          code === "CANDIDATE_PATCH_TOO_LARGE" ||
          code === "BASE_DRIFT";
        this.#core.failAttempt(
          attemptId,
          policyViolation ? "POLICY_VIOLATION" : "HARNESS_FAILED",
          code,
          null,
          { cause: error instanceof Error ? error.message : String(error) },
        );
      }
      throw error;
    } finally {
      if (requestId && provisioned) {
        try {
          await this.#broker.terminate(requestId, attemptId);
        } catch {
          // Preserve the primary execution outcome. A failed cleanup is surfaced
          // by the lease release below if mounted runtime state remains.
        }
      }
      if (lease) {
        try {
          await this.#broker.releaseWorkspaceLease(lease);
        } catch (error) {
          if (promoted) {
            throw new ControllerError(
              "WORKSPACE_RELEASE_FAILED",
              "Candidate was promoted but broker workspace cleanup failed",
              { cause: error instanceof Error ? error.message : String(error) },
            );
          }
        }
      }
    }
  }
}

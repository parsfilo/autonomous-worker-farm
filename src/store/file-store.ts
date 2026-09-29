import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type {
  GitHubMergeReceipt,
  GitHubPrPublication,
  GitIntegrationArtifact,
  IndependentReviewReport,
  MachineCapability,
  PostMergeVerificationReport,
  RemoteVerificationReport,
  GitHubActionsExecutionReceipt,
  RepoPassport,
  ResultManifest,
  SandboxAttestation,
  ValidationPlan,
  VerificationReport,
  TaskSpec,
  TaskState,
  TaskStateEvent,
} from "../../contracts/types.js";

export interface StoredPassport {
  passport: RepoPassport;
  sha256: string;
}

export interface StoredTask {
  spec: TaskSpec;
  state: TaskState;
  revision: number;
  attemptCount: number;
  events: TaskStateEvent[];
}

export interface StoredRepoSource {
  repo_id: string;
  kind: "github-public";
  remote_url: string;
  registered_at: string;
}

export type StoredAttemptState =
  | "LEASED"
  | "PROVISIONING"
  | "RUNNING"
  | "EVIDENCE_COLLECT"
  | "LOCAL_VERIFY"
  | "CANDIDATE"
  | "FAILED"
  | "LOST"
  | "CANCELLED";

export interface StoredAttempt {
  attempt_id: string;
  task_id: string;
  attempt_no: number;
  machine_id: string;
  harness_adapter: string;
  model: {
    provider: "opencode";
    model: string;
  };
  state: StoredAttemptState;
  leased_at: string;
  expires_at: string;
  correlation_id: string;
  actor_id: string;
  diversity_source_attempt_id: string | null;
  execution_backend?: "local-broker" | "github-actions";
  github_actions_dispatch?: {
    worker_repo: string;
    workflow: string;
    dispatch_ref: string;
    workflow_run_id: number;
    run_url: string;
    workflow_sha: string;
  } | null;
  github_actions_execution?: GitHubActionsExecutionReceipt | null;
  request_id?: string | null;
  workspace_lease_id?: string | null;
  run_root?: string | null;
  sandbox_request_hash?: string | null;
  workspace_read_only?: true | null;
  failure_reason?: string | null;
  started_at?: string | null;
  ended_at?: string | null;
  exit_code?: number | null;
  slot_released?: boolean;
  sandbox_attestation?: SandboxAttestation | null;
  result_manifest?: ResultManifest | null;
  patch_path?: string | null;
  validation_plan?: ValidationPlan | null;
  verification_report?: VerificationReport | null;
  integration_candidate?: GitIntegrationArtifact | null;
  pull_request?: GitHubPrPublication | null;
  remote_verification_report?: RemoteVerificationReport | null;
  merge_receipt?: GitHubMergeReceipt | null;
  post_merge_verification_report?: PostMergeVerificationReport | null;
}



export type StoredReviewState =
  | "READY"
  | "LEASED"
  | "PROVISIONING"
  | "RUNNING"
  | "SUCCEEDED"
  | "BLOCKED"
  | "FAILED"
  | "LOST";

export interface StoredReviewRun {
  review_id: string;
  task_id: string;
  source_attempt_id: string;
  candidate_hash: string;
  patch_sha256: string;
  state: StoredReviewState;
  correlation_id: string;
  actor_id: string;
  created_at: string;
  execution_backend?: "local-broker" | "github-actions";
  github_actions_dispatch?: {
    worker_repo: string;
    workflow: string;
    dispatch_ref: string;
    workflow_run_id: number;
    run_url: string;
    workflow_sha: string;
  } | null;
  github_actions_execution?: GitHubActionsExecutionReceipt | null;
  machine_id?: string | null;
  model?: { provider: "opencode"; model: string } | null;
  leased_at?: string | null;
  expires_at?: string | null;
  request_id?: string | null;
  workspace_lease_id?: string | null;
  run_root?: string | null;
  sandbox_request_hash?: string | null;
  workspace_read_only?: true | null;
  failure_reason?: string | null;
  started_at?: string | null;
  ended_at?: string | null;
  exit_code?: number | null;
  slot_released?: boolean;
  sandbox_attestation?: SandboxAttestation | null;
  report?: IndependentReviewReport | null;
}

export interface StoredModelCooldown {
  model: string;
  reason: "MODEL_RATE_LIMITED";
  source_attempt_id: string;
  observed_at: string;
  until: string;
}

export interface ControllerSnapshot {
  schema_version: "1.0";
  revision: number;
  passports: Record<string, StoredPassport>;
  repoSources: Record<string, StoredRepoSource>;
  machines: Record<string, MachineCapability>;
  tasks: Record<string, StoredTask>;
  attempts: Record<string, StoredAttempt>;
  reviews: Record<string, StoredReviewRun>;
  modelCooldowns: Record<string, StoredModelCooldown>;
  idempotency: Record<string, unknown>;
}

function emptySnapshot(): ControllerSnapshot {
  return {
    schema_version: "1.0",
    revision: 0,
    passports: {},
    repoSources: {},
    machines: {},
    tasks: {},
    attempts: {},
    reviews: {},
    modelCooldowns: {},
    idempotency: {},
  };
}

export class FileStateStore {
  readonly #path: string;
  readonly #lockPath: string;
  #snapshot: ControllerSnapshot;

  constructor(path: string) {
    this.#path = path;
    this.#lockPath = path + ".lock";
    this.#snapshot = this.#load();
  }

  get snapshot(): ControllerSnapshot {
    // Another local Controller process may have committed a newer revision.
    // Atomic rename ensures this read observes one complete snapshot version.
    this.#snapshot = this.#load();
    return structuredClone(this.#snapshot);
  }

  replace(snapshot: ControllerSnapshot): void {
    const release = this.#acquireLock();
    try {
      this.#snapshot = structuredClone(snapshot);
      this.#persist();
    } finally {
      release();
    }
  }

  mutate<T>(fn: (snapshot: ControllerSnapshot) => T): T {
    const release = this.#acquireLock();
    try {
      // Reload after taking the process-shared lock so two Controller
      // processes cannot clone one revision and overwrite each other.
      this.#snapshot = this.#load();
      const draft = structuredClone(this.#snapshot);
      const result = fn(draft);
      draft.revision += 1;
      this.#snapshot = draft;
      this.#persist();
      return result;
    } finally {
      release();
    }
  }

  #load(): ControllerSnapshot {
    if (!existsSync(this.#path)) return emptySnapshot();
    const parsed = JSON.parse(readFileSync(this.#path, "utf8")) as ControllerSnapshot;
    if (parsed.schema_version !== "1.0") {
      throw new Error("Unsupported controller snapshot schema: " + String(parsed.schema_version));
    }
    parsed.repoSources ??= {};
    parsed.attempts ??= {};
    parsed.reviews ??= {};
    parsed.modelCooldowns ??= {};
    return parsed;
  }

  #acquireLock(): () => void {
    mkdirSync(dirname(this.#path), { recursive: true, mode: 0o700 });
    const deadline = Date.now() + 5_000;
    const sleeper = new Int32Array(new SharedArrayBuffer(4));

    for (;;) {
      try {
        mkdirSync(this.#lockPath, { mode: 0o700 });
        writeFileSync(
          join(this.#lockPath, "owner.json"),
          JSON.stringify({ pid: process.pid, created_at_ms: Date.now() }) + "\n",
          { encoding: "utf8", mode: 0o600 },
        );
        return () => rmSync(this.#lockPath, { recursive: true, force: true });
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "EEXIST") throw error;

        if (this.#lockIsStale()) {
          rmSync(this.#lockPath, { recursive: true, force: true });
          continue;
        }
        if (Date.now() >= deadline) {
          throw new Error("Timed out acquiring Controller state lock");
        }
        Atomics.wait(sleeper, 0, 0, 10);
      }
    }
  }

  #lockIsStale(): boolean {
    const staleAfterMs = 30_000;
    try {
      const owner = JSON.parse(
        readFileSync(join(this.#lockPath, "owner.json"), "utf8"),
      ) as { pid?: unknown; created_at_ms?: unknown };
      if (
        typeof owner.pid === "number" &&
        Number.isInteger(owner.pid) &&
        owner.pid > 0 &&
        typeof owner.created_at_ms === "number" &&
        Date.now() - owner.created_at_ms > staleAfterMs
      ) {
        try {
          process.kill(owner.pid, 0);
          return false;
        } catch (error) {
          return (error as NodeJS.ErrnoException).code === "ESRCH";
        }
      }
      return false;
    } catch {
      try {
        return Date.now() - statSync(this.#lockPath).mtimeMs > staleAfterMs;
      } catch {
        return false;
      }
    }
  }

  #persist(): void {
    mkdirSync(dirname(this.#path), { recursive: true, mode: 0o700 });
    const tmp = this.#path + ".tmp-" + process.pid;
    writeFileSync(tmp, JSON.stringify(this.#snapshot, null, 2) + "\n", {
      encoding: "utf8",
      mode: 0o600,
    });
    renameSync(tmp, this.#path);
  }
}

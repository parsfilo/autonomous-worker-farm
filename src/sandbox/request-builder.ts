import type {
  EgressProfile,
  SandboxRequest,
  SandboxTier,
  SandboxWorkspaceLease,
  TaskSpec,
} from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { ControllerError } from "../lib/errors.js";
import { OPENCODE_FIXED_RUN_ARGV } from "../harness/opencode/adapter.js";
import { resolveEgressRoute, type ResolvedEgressRoute } from "./egress-profile.js";

export interface SandboxRuntimeImage {
  reference: string;
  digest: string;
}

export interface SandboxResourceRequest {
  cpu: number;
  memory_bytes: number;
  pids: number;
  tmpfs_bytes: number;
  timeout_seconds: number;
}

export type SandboxNetworkSelection =
  | {
      profile: "none";
    }
  | {
      profile: "brokered";
      egressProfile: EgressProfile;
      routeId: string;
      model: string;
    };

export interface BuildSandboxRequestInput {
  requestId: string;
  attemptId: string;
  task: TaskSpec;
  machineId: string;
  tier: SandboxTier;
  lease: SandboxWorkspaceLease;
  image: SandboxRuntimeImage;
  resources: SandboxResourceRequest;
  policyHash: string;
  network: SandboxNetworkSelection;
  authorizationTtlSeconds?: number;
  now?: Date;
  workspaceReadOnly?: boolean;
}

export interface BuiltSandboxRequest {
  request: SandboxRequest;
  resolvedEgress: ResolvedEgressRoute | null;
  openCodeProvider:
    | {
        model: string;
        providers: Record<string, unknown>;
      }
    | null;
  selectedModel: string | null;
  proxyURL: string | null;
}

function rfc3339Seconds(value: Date): string {
  return value.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function assertLeaseBinding(
  lease: SandboxWorkspaceLease,
  attemptId: string,
  machineId: string,
): void {
  if (lease.attempt_id !== attemptId) {
    throw new ControllerError(
      "SANDBOX_LEASE_BINDING_MISMATCH",
      "Workspace lease attempt_id does not match sandbox attempt",
    );
  }
  if (lease.machine_id !== machineId) {
    throw new ControllerError(
      "SANDBOX_LEASE_BINDING_MISMATCH",
      "Workspace lease machine_id does not match sandbox machine",
    );
  }
  if (!lease.immutable_parent) {
    throw new ControllerError(
      "SANDBOX_LEASE_INVALID",
      "Workspace lease must have an immutable broker-owned parent",
    );
  }
  if (
    lease.paths.repo !== lease.paths.run_root + "/repo" ||
    lease.paths.control !== lease.paths.run_root + "/control" ||
    lease.paths.artifacts !== lease.paths.run_root + "/artifacts"
  ) {
    throw new ControllerError(
      "SANDBOX_LEASE_INVALID",
      "Workspace lease child paths must be derived from run_root",
    );
  }
}

function authorizationExpiry(
  lease: SandboxWorkspaceLease,
  now: Date,
  ttlSeconds: number,
): string {
  if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 600) {
    throw new ControllerError(
      "SANDBOX_AUTHORIZATION_TTL_INVALID",
      "Sandbox authorization TTL must be an integer between 1 and 600 seconds",
    );
  }

  const leaseExpiry = new Date(lease.expires_at);
  if (!Number.isFinite(leaseExpiry.getTime()) || leaseExpiry.getTime() <= now.getTime()) {
    throw new ControllerError("SANDBOX_LEASE_EXPIRED", "Workspace lease is already expired");
  }

  const requested = new Date(now.getTime() + ttlSeconds * 1000);
  const effective = new Date(Math.min(requested.getTime(), leaseExpiry.getTime()));
  if (effective.getTime() <= now.getTime()) {
    throw new ControllerError(
      "SANDBOX_AUTHORIZATION_EXPIRED",
      "Sandbox authorization window is empty",
    );
  }
  return rfc3339Seconds(effective);
}

export function buildSandboxRequest(
  input: BuildSandboxRequestInput,
  contracts = new ContractRegistry(),
): BuiltSandboxRequest {
  const task = contracts.validate<TaskSpec>("task-spec", input.task);
  const lease = contracts.validate<SandboxWorkspaceLease>("sandbox-workspace-lease", input.lease);
  assertLeaseBinding(lease, input.attemptId, input.machineId);

  if (task.task_id.length === 0) {
    throw new ControllerError("SANDBOX_TASK_INVALID", "Task id is required");
  }
  if (task.base_sha.length !== 40) {
    throw new ControllerError("SANDBOX_BASE_SHA_INVALID", "Task base SHA must be a 40-character Git SHA");
  }
  if (!/^[0-9a-f]{64}$/.test(input.policyHash)) {
    throw new ControllerError("SANDBOX_POLICY_HASH_INVALID", "policyHash must be lowercase SHA-256");
  }
  const now = input.now ?? new Date();
  const expiresAt = authorizationExpiry(
    lease,
    now,
    input.authorizationTtlSeconds ?? Math.min(task.lease_ttl_seconds, 300),
  );

  let network: SandboxRequest["network"];
  let resolvedEgress: ResolvedEgressRoute | null = null;
  let openCodeProvider: BuiltSandboxRequest["openCodeProvider"] = null;
  let selectedModel: string | null = null;
  let proxyURL: string | null = null;

  if (input.network.profile === "none") {
    if (task.network_profile !== "none") {
      throw new ControllerError(
        "SANDBOX_NETWORK_PROFILE_MISMATCH",
        "Task requires network profile " + task.network_profile + " but sandbox request selected none",
      );
    }
    network = {
      profile: "none",
      egress_profile_id: null,
      egress_profile_hash: null,
      route_id: null,
      model: null,
    };
  } else {
    resolvedEgress = resolveEgressRoute(
      input.network.egressProfile,
      input.network.routeId,
      input.network.model,
      contracts,
    );
    const isOpenCodeFree =
      resolvedEgress.route.protocol === "opencode-free-connect";
    if (isOpenCodeFree && task.network_profile !== "opencode-free") {
      throw new ControllerError(
        "SANDBOX_NETWORK_PROFILE_MISMATCH",
        "opencode-free-connect requires TaskSpec network_profile=opencode-free",
      );
    }
    if (!isOpenCodeFree && task.network_profile !== "none") {
      throw new ControllerError(
        "SANDBOX_WORKLOAD_NETWORK_UNIMPLEMENTED",
        "Secret-backed model egress does not authorize workload network profile " +
          task.network_profile,
      );
    }

    network = {
      profile: "brokered",
      egress_profile_id: resolvedEgress.profile.profile_id,
      egress_profile_hash: resolvedEgress.profileHash,
      route_id: resolvedEgress.route.route_id,
      model: resolvedEgress.model,
    };
    openCodeProvider = resolvedEgress.openCodeProvider;
    selectedModel = resolvedEgress.model;
    proxyURL = resolvedEgress.proxyURL;
  }

  const request: SandboxRequest = {
    schema_version: "1.0",
    request_id: input.requestId,
    task_id: task.task_id,
    attempt_id: input.attemptId,
    machine_id: input.machineId,
    tier: input.tier,
    run_root: lease.paths.run_root,
    workspace: {
      source: lease.paths.repo,
      mount_path: "/workspace",
      read_only: input.workspaceReadOnly ?? false,
      base_sha: task.base_sha,
      controller_gid: lease.controller_gid,
    },
    image: {
      reference: input.image.reference,
      digest: input.image.digest,
    },
    network,
    resources: {
      cpu: input.resources.cpu,
      memory_bytes: input.resources.memory_bytes,
      pids: input.resources.pids,
      tmpfs_bytes: input.resources.tmpfs_bytes,
      timeout_seconds: input.resources.timeout_seconds,
    },
    command: {
      argv: [...OPENCODE_FIXED_RUN_ARGV],
      env_allowlist: [],
    },
    policy_hash: input.policyHash,
    expires_at: expiresAt,
    workspace_lease_id: lease.lease_id,
    workspace_lease_hash: lease.lease_hash,
  };

  return {
    request: contracts.validate<SandboxRequest>("sandbox-request", request),
    resolvedEgress,
    openCodeProvider,
    selectedModel,
    proxyURL,
  };
}

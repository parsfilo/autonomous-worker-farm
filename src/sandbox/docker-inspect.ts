import { resolve } from "node:path";
import type { SandboxAttestation, SandboxRequest } from "../../contracts/types.js";
import { computeSandboxRequestBindingHash } from "./request-binding.js";
import { ControllerError } from "../lib/errors.js";
import type { DockerSandboxSpec } from "./docker-spec.js";

export interface DockerInspectLike {
  Id?: unknown;
  Config?: {
    Image?: unknown;
    User?: unknown;
    Labels?: Record<string, unknown> | null;
  } | null;
  HostConfig?: {
    NetworkMode?: unknown;
    ReadonlyRootfs?: unknown;
    CapDrop?: unknown;
    SecurityOpt?: unknown;
    PidsLimit?: unknown;
    Memory?: unknown;
  } | null;
  Mounts?: Array<{
    Source?: unknown;
    Destination?: unknown;
    RW?: unknown;
  }> | null;
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ControllerError("DOCKER_INSPECT_INVALID", label + " must be an object");
  }
  return value as Record<string, unknown>;
}

function parseNonRootUser(value: unknown): { uid: number; gid: number } {
  if (typeof value !== "string" || !value) {
    throw new ControllerError("DOCKER_INSPECT_INVALID", "Container Config.User must be explicit");
  }
  const [uidText, gidText] = value.split(":", 2);
  const uid = Number.parseInt(uidText ?? "", 10);
  const gid = Number.parseInt(gidText ?? "", 10);
  if (!Number.isInteger(uid) || uid <= 0 || !Number.isInteger(gid) || gid <= 0) {
    throw new ControllerError(
      "DOCKER_INSPECT_INVALID",
      "Container must run as an explicit numeric non-root UID:GID",
      { user: value },
    );
  }
  return { uid, gid };
}

export function attestationFromDockerInspect(
  request: SandboxRequest,
  spec: DockerSandboxSpec,
  inspectInput: unknown,
  options: {
    brokerBuild: string;
    actualImageDigest: string;
    landlockAbi: number | null;
    daemonSeccomp: boolean;
    daemonAppArmor: boolean;
    daemonCgroups: boolean;
  },
): SandboxAttestation {
  if (request.network.profile !== "none") {
    throw new ControllerError(
      "DOCKER_INSPECT_BROKERED_UNSUPPORTED",
      "Offline Docker inspect helper cannot attest brokered egress; use the privileged broker attestation",
    );
  }
  const inspect = requireObject(inspectInput, "docker inspect");
  const config = requireObject(inspect.Config, "Config");
  const host = requireObject(inspect.HostConfig, "HostConfig");
  const mountsRaw = inspect.Mounts;

  if (!Array.isArray(mountsRaw)) {
    throw new ControllerError("DOCKER_INSPECT_INVALID", "Mounts must be an array");
  }

  if (config.Image !== spec.expectedImage) {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Container image reference differs from pinned spec");
  }
  if (options.actualImageDigest !== request.image.digest) {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Resolved image digest differs from SandboxRequest");
  }
  if (host.NetworkMode !== "none") {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Container network mode is not none");
  }
  if (host.ReadonlyRootfs !== true) {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Container root filesystem is not read-only");
  }

  const capDrop = Array.isArray(host.CapDrop) ? host.CapDrop : [];
  if (!capDrop.includes("ALL")) {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Container does not drop all Linux capabilities");
  }

  const securityOpt = Array.isArray(host.SecurityOpt) ? host.SecurityOpt : [];
  if (!securityOpt.some((value) => value === "no-new-privileges:true")) {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "no-new-privileges is not enabled");
  }

  const process = parseNonRootUser(config.User);
  if (process.uid !== spec.processUid || process.gid !== spec.processGid) {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Container UID:GID differs from sandbox spec", {
      expectedUid: spec.processUid,
      expectedGid: spec.processGid,
      actualUid: process.uid,
      actualGid: process.gid,
    });
  }

  const expected = new Map(
    spec.expectedMounts.map((mount) => [
      mount.destination,
      { source: resolve(mount.source), readOnly: mount.readOnly },
    ]),
  );
  const observed = new Set<string>();

  for (const raw of mountsRaw) {
    const mount = requireObject(raw, "Mount");
    const destination = mount.Destination;
    const source = mount.Source;
    const rw = mount.RW;

    if (typeof destination !== "string" || typeof source !== "string" || typeof rw !== "boolean") {
      throw new ControllerError("DOCKER_INSPECT_INVALID", "Mount fields have invalid types");
    }

    const expectedMount = expected.get(destination as DockerSandboxSpec["expectedMounts"][number]["destination"]);
    if (!expectedMount) {
      throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Unexpected host bind mount", {
        destination,
        source,
      });
    }
    if (resolve(source) !== expectedMount.source || rw === expectedMount.readOnly) {
      throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Mount does not match sandbox spec", {
        destination,
        source,
        rw,
      });
    }
    observed.add(destination);
  }

  for (const destination of expected.keys()) {
    if (!observed.has(destination)) {
      throw new ControllerError("DOCKER_INSPECT_MISMATCH", "Required mount is missing", {
        destination,
      });
    }
  }

  const labels: Record<string, unknown> =
    config.Labels && typeof config.Labels === "object" && !Array.isArray(config.Labels)
      ? (config.Labels as Record<string, unknown>)
      : {};
  if (
    labels["awf.role"] !== "worker" ||
    labels["awf.request_id"] !== request.request_id ||
    labels["awf.task_id"] !== request.task_id ||
    labels["awf.attempt_id"] !== request.attempt_id ||
    labels["awf.workspace_lease_id"] !== request.workspace_lease_id
  ) {
    throw new ControllerError("DOCKER_INSPECT_MISMATCH", "AWF identity labels do not match request");
  }

  const containerId = inspect.Id;
  if (typeof containerId !== "string" || !containerId) {
    throw new ControllerError("DOCKER_INSPECT_INVALID", "Container Id is missing");
  }

  return {
    schema_version: "1.0",
    request_id: request.request_id,
    task_id: request.task_id,
    attempt_id: request.attempt_id,
    machine_id: request.machine_id,
    status: "PROVISIONED",
    tier: request.tier,
    broker: {
      kind: "privileged-docker",
      build: options.brokerBuild,
    },
    sandbox: {
      landlock_abi: options.landlockAbi,
      container_runtime: "docker",
      user_namespace: false,
      seccomp: options.daemonSeccomp,
      apparmor: options.daemonAppArmor,
      cgroups: options.daemonCgroups,
      network_profile: "none",
      network_enforced: host.NetworkMode === "none",
      remote_git_write_credential_present: false,
      docker_socket_present: false,
      host_home_mounted: false,
      process_uid: process.uid,
      process_gid: process.gid,
      capabilities_dropped: true,
      read_only_rootfs: true,
      no_new_privileges: true,
    },
    egress: null,
    image_digest: options.actualImageDigest,
    container_id: containerId,
    started_at: new Date().toISOString(),
    ended_at: null,
    exit_code: null,
    request_hash: computeSandboxRequestBindingHash(request),
    evidence_hash: null,
    rejection_code: null,
    details: {
      pids_limit: host.PidsLimit ?? null,
      memory_limit: host.Memory ?? null,
    },
  };
}

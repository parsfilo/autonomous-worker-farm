import { createHash } from "node:crypto";
import { resolve, sep } from "node:path";
import type { SandboxRequest } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";

export const DEFAULT_BROKER_RUNS_ROOT = "/var/lib/autonomous-worker/runs";
export const WORKER_UID = 65532;

export interface DockerSandboxSpec {
  containerName: string;
  createArgs: string[];
  expectedMounts: Array<{
    source: string;
    destination: "/run" | "/run/repo" | "/run/control" | "/run/artifacts";
    readOnly: boolean;
  }>;
  expectedImage: string;
  processUid: number;
  processGid: number;
}

function assertUnder(parent: string, child: string, label: string): void {
  const parentResolved = resolve(parent);
  const childResolved = resolve(child);
  if (childResolved !== parentResolved && !childResolved.startsWith(parentResolved + sep)) {
    throw new ControllerError("SANDBOX_PATH_OUTSIDE_ROOT", label + " is outside the approved run root", {
      parent: parentResolved,
      child: childResolved,
    });
  }
}

function boundedDockerName(prefix: string, identity: string): string {
  let safe = identity.toLowerCase().replace(/[^a-z0-9_.-]/g, "-");
  if (!safe) {
    throw new ControllerError("SANDBOX_NAME_INVALID", "attempt_id cannot form a Docker name");
  }
  const suffix = createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 12);
  const maxIdentity = Math.max(1, 63 - prefix.length - suffix.length - 2);
  safe = safe.slice(0, maxIdentity);
  return prefix + "-" + safe + "-" + suffix;
}

function pinnedImage(request: SandboxRequest): string {
  if (request.image.reference.includes("@")) {
    const [name, digest] = request.image.reference.split("@", 2);
    if (!name || digest !== request.image.digest) {
      throw new ControllerError(
        "SANDBOX_IMAGE_DIGEST_MISMATCH",
        "Image reference digest does not match SandboxRequest.image.digest",
      );
    }
    return request.image.reference;
  }
  return request.image.reference + "@" + request.image.digest;
}

export function buildDockerSandboxSpec(
  request: SandboxRequest,
  brokerRunsRoot = DEFAULT_BROKER_RUNS_ROOT,
): DockerSandboxSpec {
  if (request.tier !== "T1") {
    throw new ControllerError(
      "SANDBOX_TIER_UNSUPPORTED",
      "Phase 1 privileged Docker broker supports T1 only",
      { requestedTier: request.tier },
    );
  }
  if (request.network.profile !== "none") {
    throw new ControllerError(
      "SANDBOX_NETWORK_PROFILE_UNSUPPORTED",
      "Offline Docker spec helper supports only network:none; brokered egress is compiled by the privileged Go broker",
    );
  }

  const runsRoot = resolve(brokerRunsRoot);
  const runRoot = resolve(request.run_root);
  assertUnder(runsRoot, runRoot, "run_root");

  const expectedRunRoot = resolve(runsRoot, request.attempt_id);
  if (runRoot !== expectedRunRoot) {
    throw new ControllerError(
      "SANDBOX_RUN_ROOT_INVALID",
      "run_root must be derived from broker runs root and attempt_id",
      { expected: expectedRunRoot, actual: runRoot },
    );
  }

  const expectedRepo = resolve(runRoot, "repo");
  const workspaceSource = resolve(request.workspace.source);
  if (workspaceSource !== expectedRepo) {
    throw new ControllerError(
      "SANDBOX_WORKSPACE_SOURCE_INVALID",
      "workspace.source must be the broker-derived run_root/repo path",
      { expected: expectedRepo, actual: workspaceSource },
    );
  }

  const control = resolve(runRoot, "control");
  const artifacts = resolve(runRoot, "artifacts");
  [workspaceSource, control, artifacts].forEach((path) => assertUnder(runRoot, path, "sandbox mount"));

  const processUid = WORKER_UID;
  const processGid = request.workspace.controller_gid;
  if (!Number.isInteger(processGid) || processGid <= 0) {
    throw new ControllerError("SANDBOX_GID_INVALID", "workspace.controller_gid must be a positive integer");
  }

  const containerName = boundedDockerName("awf-worker", request.attempt_id);
  const expectedImage = pinnedImage(request);

  const expectedMounts: DockerSandboxSpec["expectedMounts"] = [
    { source: runRoot, destination: "/run", readOnly: true },
    { source: workspaceSource, destination: "/run/repo", readOnly: request.workspace.read_only },
    { source: control, destination: "/run/control", readOnly: true },
    { source: artifacts, destination: "/run/artifacts", readOnly: false },
  ];

  const mount = (source: string, destination: string, readOnly: boolean) =>
    "type=bind,src=" + source + ",dst=" + destination + (readOnly ? ",readonly" : "");

  const args = [
    "create",
    "--name",
    containerName,
    "--label",
    "awf.role=worker",
    "--label",
    "awf.request_id=" + request.request_id,
    "--label",
    "awf.task_id=" + request.task_id,
    "--label",
    "awf.attempt_id=" + request.attempt_id,
    "--label",
    "awf.workspace_lease_id=" + request.workspace_lease_id,
    "--network",
    "none",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges:true",
    "--pids-limit",
    String(request.resources.pids),
    "--memory",
    String(request.resources.memory_bytes),
    "--cpus",
    String(request.resources.cpu),
    "--tmpfs",
    "/tmp:rw,noexec,nosuid,nodev,size=" + request.resources.tmpfs_bytes + ",mode=1777",
    "--tmpfs",
    "/home/worker:rw,nosuid,nodev,size=67108864,uid=65532,gid=" + request.workspace.controller_gid + ",mode=0700",
    "--user",
    String(processUid) + ":" + String(processGid),
    "--workdir",
    "/run",
  ];

  for (const expectedMount of expectedMounts) {
    args.push("--mount", mount(expectedMount.source, expectedMount.destination, expectedMount.readOnly));
  }

  args.push(
    "--env",
    "HOME=/home/worker",
    "--env",
    "XDG_CONFIG_HOME=/tmp/.config",
    "--env",
    "XDG_CACHE_HOME=/tmp/.cache",
    "--env",
    "XDG_DATA_HOME=/tmp/.local/share",
    "--env",
    "TMPDIR=/tmp",
    "--env",
    "OPENCODE_DISABLE_PROJECT_CONFIG=1",
    "--env",
    "OPENCODE_CONFIG_DIR=/run/control/opencode",
    "--env",
    "OPENCODE_DB=:memory:",
    "--env",
    "AWF_REPO_DIR=/run/repo",
    "--env",
    "AWF_ARTIFACT_DIR=/run/artifacts",
    "--env",
    "AWF_TASK_ID=" + request.task_id,
    "--env",
    "AWF_ATTEMPT_ID=" + request.attempt_id,
    "--env",
    "GIT_CONFIG_COUNT=1",
    "--env",
    "GIT_CONFIG_KEY_0=safe.directory",
    "--env",
    "GIT_CONFIG_VALUE_0=/run/repo",
    "--env",
    "GIT_TERMINAL_PROMPT=0",
    expectedImage,
    ...request.command.argv,
  );

  return {
    containerName,
    createArgs: args,
    expectedMounts,
    expectedImage,
    processUid,
    processGid,
  };
}

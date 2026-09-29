import { execFile } from "node:child_process";
import { accessSync, constants, existsSync, readFileSync, statfsSync } from "node:fs";
import { availableParallelism, cpus, platform, release, totalmem } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { MachineCapability, ModelClass, RiskClass } from "../../contracts/types.js";
import { OPENCODE_HARNESS_CAPABILITIES } from "../harness/opencode/adapter.js";
import { loadOpenCodeFreeRoutingPolicy, type OpenCodeFreeRoutingPolicy } from "../models/opencode-free-routing.js";
import { loadOpenCodeFreeRuntimeState, schedulableClassesFromRuntimeState, type OpenCodeFreeRuntimeState } from "../models/opencode-free-runtime-state.js";
import { SandboxBrokerClient, type SandboxBrokerHealth } from "../sandbox/broker-client.js";
import { findProjectRoot } from "../lib/project-root.js";

const execFileAsync = promisify(execFile);

export function normalizeLogicalCpuCount(
  available: number,
  detected: number,
): number {
  const candidates = [available, detected].filter(
    (value) => Number.isInteger(value) && value > 0,
  );
  return candidates.length > 0 ? Math.max(...candidates) : 1;
}

function logicalCpuCount(): number {
  let available = 0;
  try {
    available = availableParallelism();
  } catch {
    available = 0;
  }
  return normalizeLogicalCpuCount(available, cpus().length);
}

interface LockedWorkerRuntime {
  digest: string;
  toolchain: { opencode: string };
}

export function loadLockedWorkerRuntime(projectRoot: string): LockedWorkerRuntime {
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      readFileSync(join(projectRoot, "containers", "runtime-images.lock.json"), "utf8"),
    );
  } catch (error) {
    throw new Error(
      "could not read runtime image lock: " +
        (error instanceof Error ? error.message : String(error)),
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("runtime image lock must be an object");
  }
  const worker = (parsed as Record<string, unknown>).worker;
  if (!worker || typeof worker !== "object" || Array.isArray(worker)) {
    throw new Error("runtime image lock is missing worker evidence");
  }
  const value = worker as Record<string, unknown>;
  const toolchain = value.toolchain;
  if (!toolchain || typeof toolchain !== "object" || Array.isArray(toolchain)) {
    throw new Error("runtime image lock is missing worker toolchain evidence");
  }
  const opencode = (toolchain as Record<string, unknown>).opencode;
  if (
    typeof value.digest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(value.digest) ||
    typeof opencode !== "string" ||
    !/^\d+\.\d+\.\d+$/.test(opencode)
  ) {
    throw new Error("runtime image lock contains invalid worker harness evidence");
  }
  return {
    digest: value.digest,
    toolchain: { opencode },
  };
}

export interface LockedBrokerRuntime {
  buildId: string;
  buildSha256: string;
  goVersion: string;
  sourceManifestSha256: string;
}

export function loadLockedBrokerRuntime(projectRoot: string): LockedBrokerRuntime {
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      readFileSync(join(projectRoot, "deploy", "broker-runtime.lock.json"), "utf8"),
    );
  } catch (error) {
    throw new Error(
      "could not read broker runtime lock: " +
        (error instanceof Error ? error.message : String(error)),
    );
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("broker runtime lock must be an object");
  }
  const value = parsed as Record<string, unknown>;
  const sha =
    typeof value.build_sha256 === "string" ? value.build_sha256 : "";
  const buildId =
    typeof value.build_id === "string" ? value.build_id : "";
  const goVersion =
    typeof value.go_version === "string" ? value.go_version : "";
  const sourceManifestSha256 =
    typeof value.source_manifest_sha256 === "string"
      ? value.source_manifest_sha256
      : "";
  if (
    value.schema_version !== "1.0" ||
    !/^[0-9a-f]{64}$/.test(sha) ||
    buildId !== "sha256:" + sha ||
    !/^go\d+\.\d+\.\d+$/.test(goVersion) ||
    !/^[0-9a-f]{64}$/.test(sourceManifestSha256)
  ) {
    throw new Error("broker runtime lock contains invalid build evidence");
  }
  return {
    buildId,
    buildSha256: sha,
    goVersion,
    sourceManifestSha256,
  };
}

export interface BrokeredFreeCapability {
  ready: boolean;
  networkProfiles: string[];
  modelClasses: ModelClass[];
  containerRuntime: string | null;
  networkPolicy: boolean;
  trustCeiling: RiskClass;
  brokerBuild: string | null;
}

export function deriveBrokeredFreeCapability(
  machineId: string,
  health: SandboxBrokerHealth | null,
  state: OpenCodeFreeRuntimeState | null,
  policy: OpenCodeFreeRoutingPolicy | null,
  expectedBrokerBuild: string | null,
): BrokeredFreeCapability {
  const disabled: BrokeredFreeCapability = {
    ready: false,
    networkProfiles: [],
    modelClasses: [],
    containerRuntime: null,
    networkPolicy: false,
    trustCeiling: "LOW",
    brokerBuild: null,
  };

  if (!health || !state || !policy || !expectedBrokerBuild) return disabled;
  if (
    health.status !== "ready" ||
    health.broker_build !== expectedBrokerBuild ||
    !health.runtime_ready ||
    !health.workspace_manager_ready ||
    health.machine_id !== machineId ||
    state.machine_id !== machineId
  ) {
    return disabled;
  }

  const modelClasses = schedulableClassesFromRuntimeState(state, policy);
  if (modelClasses.length === 0) return disabled;

  return {
    ready: true,
    networkProfiles: ["none", "opencode-free"],
    modelClasses,
    containerRuntime: "docker-broker",
    networkPolicy: true,
    trustCeiling: "MEDIUM",
    brokerBuild: health.broker_build,
  };
}

async function commandVersion(command: string, args: string[] = ["--version"]): Promise<string | null> {
  try {
    const { stdout, stderr } = await execFileAsync(command, args, {
      timeout: 10_000,
      maxBuffer: 1024 * 1024
    });
    const text = (stdout || stderr).trim().split("\n")[0]?.trim();
    return text || "present";
  } catch {
    return null;
  }
}

async function canUseUserNamespace(): Promise<boolean> {
  try {
    await execFileAsync("unshare", ["--user", "--map-root-user", "/bin/true"], { timeout: 5_000 });
    return true;
  } catch {
    return false;
  }
}

function cgroupV2Available(): boolean {
  return existsSync("/sys/fs/cgroup/cgroup.controllers");
}

function seccompAvailable(): boolean {
  return existsSync("/proc/sys/kernel/seccomp/actions_avail");
}

async function probeLandlockAbi(projectRoot: string): Promise<number | null> {
  const probe = join(projectRoot, "native", "bin", "landlock-probe");
  try {
    accessSync(probe, constants.X_OK);
  } catch {
    return null;
  }

  try {
    const { stdout } = await execFileAsync(probe, [], { timeout: 5_000, maxBuffer: 1024 * 1024 });
    const abi = Number.parseInt(stdout.trim(), 10);
    return Number.isInteger(abi) && abi > 0 ? abi : null;
  } catch {
    return null;
  }
}

export async function probeLocalMachine(machineId = "production-vps"): Promise<MachineCapability> {
  const projectRoot = findProjectRoot();
  const now = new Date();
  const landlockAbi = await probeLandlockAbi(projectRoot);
  const userNamespace = await canUseUserNamespace();

  let brokerCapability = deriveBrokeredFreeCapability(
    machineId,
    null,
    null,
    null,
    null,
  );
  try {
    const socketPath = process.env.AWF_BROKER_SOCKET ?? "/run/autonomous-worker/sandbox-broker.sock";
    const policyPath =
      process.env.AWF_FREE_MODEL_POLICY_PATH ??
      (existsSync("/etc/autonomous-worker/opencode-free-routing.json")
        ? "/etc/autonomous-worker/opencode-free-routing.json"
        : join(projectRoot, "policies", "opencode-free-routing.json"));
    const statePath =
      process.env.AWF_FREE_MODEL_STATE_PATH ??
      (existsSync("/var/lib/autonomous-worker/runtime-state/opencode-free.json")
        ? "/var/lib/autonomous-worker/runtime-state/opencode-free.json"
        : join(projectRoot, ".state", "opencode-free-runtime.json"));

    const health = await new SandboxBrokerClient({ socketPath, timeoutMs: 5_000 }).health();
    const policy = loadOpenCodeFreeRoutingPolicy(policyPath);
    const state = loadOpenCodeFreeRuntimeState(statePath, policy, { now });
    const brokerRuntime = loadLockedBrokerRuntime(projectRoot);
    brokerCapability = deriveBrokeredFreeCapability(
      machineId,
      health,
      state,
      policy,
      brokerRuntime.buildId,
    );
  } catch {
    // Fail closed: socket, policy or runtime evidence problems never promote capability.
  }

  const tools: Record<string, string> = {};
  const candidates: Array<[string, string, string[]]> = [
    ["node", "node", ["--version"]],
    ["pnpm", "pnpm", ["--version"]],
    ["git", "git", ["--version"]],
    ["semgrep", "semgrep", ["--version"]],
    ["codacy-analysis", "codacy-analysis", ["--version"]],
    ["sonar-scanner", "sonar-scanner", ["--version"]],
    ["docker", "docker", ["--version"]],
    ["bwrap", "bwrap", ["--version"]]
  ];

  for (const [name, command, args] of candidates) {
    const version = await commandVersion(command, args);
    if (version) tools[name] = version;
  }

  const harnesses: MachineCapability["harnesses"] = [];
  if (brokerCapability.ready) {
    try {
      const workerRuntime = loadLockedWorkerRuntime(projectRoot);
      harnesses.push({
        adapter: "opencode",
        version: workerRuntime.toolchain.opencode,
        digest: workerRuntime.digest,
        healthy: true,
        capabilities: [...OPENCODE_HARNESS_CAPABILITIES],
      });
    } catch {
      // Fail closed: execution harness evidence must come from the locked worker image.
    }
  }

  const fs = statfsSync(projectRoot);
  const diskFree = Number(fs.bavail) * Number(fs.bsize);
  const diskTotal = Number(fs.blocks) * Number(fs.bsize);
  const diskUsedPercent = diskTotal > 0 ? ((diskTotal - diskFree) / diskTotal) * 100 : 100;

  const toolProfiles: string[] = [];
  if (tools.node && tools.pnpm && tools.git) toolProfiles.push("typescript-node");
  if (tools.semgrep || tools["codacy-analysis"] || tools["sonar-scanner"]) toolProfiles.push("quality-static");
  if (brokerCapability.ready && brokerCapability.brokerBuild) {
    tools["sandbox-broker"] = brokerCapability.brokerBuild;
  }

  const cpuLogical = logicalCpuCount();

  return {
    schema_version: "1.0",
    machine_id: machineId,
    online: true,
    os: platform(),
    architecture: process.arch,
    kernel: release(),
    cpu_logical: cpuLogical,
    memory_bytes: totalmem(),
    disk_free_bytes: diskFree,
    disk_total_bytes: diskTotal,
    disk_used_percent: Number(diskUsedPercent.toFixed(2)),
    sandbox: {
      landlock: landlockAbi !== null,
      landlock_abi: landlockAbi,
      rootless_container: false,
      container_runtime: brokerCapability.containerRuntime,
      cgroups: cgroupV2Available(),
      seccomp: seccompAvailable(),
      network_policy: brokerCapability.networkPolicy
    },
    harnesses,
    tools: {
      ...tools,
      "user-namespace": userNamespace ? "available" : "unavailable"
    },
    tool_profiles: toolProfiles,
    network_profiles: brokerCapability.networkProfiles,
    model_classes: brokerCapability.modelClasses,
    max_slots: Math.max(1, Math.min(4, Math.floor(cpuLogical / 2))),
    active_slots: 0,
    trust_ceiling: brokerCapability.trustCeiling,
    last_probe_at: now.toISOString()
  };
}

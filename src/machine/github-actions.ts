import type { MachineCapability } from "../../contracts/types.js";
import { OPENCODE_HARNESS_CAPABILITIES } from "../harness/opencode/adapter.js";
import { ControllerError } from "../lib/errors.js";

export interface GitHubActionsMachineOptions {
  machineId: string;
  maxSlots?: number;
  openCodeVersion?: string;
  now?: () => Date;
}

export function githubActionsMachineCapability(
  options: GitHubActionsMachineOptions,
): MachineCapability {
  const maxSlots = options.maxSlots ?? 20;
  if (!Number.isInteger(maxSlots) || maxSlots < 1 || maxSlots > 20) {
    throw new ControllerError(
      "GITHUB_ACTIONS_SLOT_LIMIT_INVALID",
      "GitHub-hosted standard runner pool must use 1..20 Controller slots",
      { maxSlots },
    );
  }
  if (!options.machineId || options.machineId.length > 128) {
    throw new ControllerError(
      "GITHUB_ACTIONS_MACHINE_ID_INVALID",
      "GitHub Actions logical machine id is invalid",
    );
  }

  return {
    schema_version: "1.0",
    machine_id: options.machineId,
    online: true,
    os: "linux",
    architecture: "x64",
    kernel: null,
    cpu_logical: 4,
    memory_bytes: 16 * 1024 ** 3,
    disk_free_bytes: 14 * 1024 ** 3,
    disk_total_bytes: 14 * 1024 ** 3,
    disk_used_percent: 0,
    sandbox: {
      landlock: false,
      landlock_abi: null,
      rootless_container: false,
      container_runtime: "github-actions-docker",
      cgroups: true,
      seccomp: true,
      network_policy: true,
    },
    harnesses: [
      {
        adapter: "opencode",
        version: options.openCodeVersion ?? "2.0.18",
        digest: null,
        healthy: true,
        capabilities: [...OPENCODE_HARNESS_CAPABILITIES],
      },
    ],
    tools: {
      runner: "github-hosted",
      node: "24.19.0",
      opencode: options.openCodeVersion ?? "2.0.18",
      pnpm: "12.4.2",
    },
    tool_profiles: ["quality-static"],
    network_profiles: ["none", "opencode-free"],
    model_classes: ["fast", "coding", "review"],
    max_slots: maxSlots,
    active_slots: 0,
    trust_ceiling: "MEDIUM",
    last_probe_at: (options.now ?? (() => new Date()))().toISOString(),
  };
}

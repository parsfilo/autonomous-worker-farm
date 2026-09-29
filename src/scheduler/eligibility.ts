import type {
  MachineCapability,
  RepoPassport,
  RiskClass,
  SandboxTier,
  TaskSpec,
} from "../../contracts/types.js";

export type EligibilityReasonCode =
  | "MACHINE_OFFLINE"
  | "NO_SLOT_CAPACITY"
  | "DISK_PRESSURE"
  | "RISK_EXCEEDS_MACHINE_TRUST"
  | "NETWORK_PROFILE_NOT_ALLOWED_BY_REPO"
  | "NETWORK_PROFILE_UNAVAILABLE"
  | "NETWORK_POLICY_UNAVAILABLE"
  | "TOOL_PROFILE_UNAVAILABLE"
  | "MODEL_CLASS_NOT_ALLOWED_BY_REPO"
  | "MODEL_CLASS_UNAVAILABLE"
  | "HARNESS_NOT_ALLOWED_BY_REPO"
  | "HARNESS_UNAVAILABLE"
  | "HARNESS_UNHEALTHY"
  | "HARNESS_CAPABILITY_MISSING"
  | "SANDBOX_TIER_UNAVAILABLE";

export interface EligibilityReason {
  code: EligibilityReasonCode;
  detail: string;
}

export interface SchedulerAdmissionPolicy {
  diskBlockPercent: number;
  minFreeDiskBytes: number;
}

export const DEFAULT_ADMISSION_POLICY: SchedulerAdmissionPolicy = {
  diskBlockPercent: 85,
  minFreeDiskBytes: 10 * 1024 ** 3,
};

export interface EligibilityResult {
  eligible: boolean;
  reasons: EligibilityReason[];
  eligibleHarnesses: string[];
  requiredSandboxTier: SandboxTier;
  score: number;
}

const riskRank: Record<RiskClass, number> = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  PROTECTED: 3,
};

const sandboxRank: Record<SandboxTier, number> = {
  T0: 0,
  T1: 1,
  T2: 2,
};

function defaultSandboxTier(task: TaskSpec): SandboxTier {
  if (task.harness_requirements.minimum_sandbox_tier) return task.harness_requirements.minimum_sandbox_tier;
  if (task.risk_class === "LOW" && task.write_scope.length === 0) return "T0";
  if (task.risk_class === "PROTECTED") return "T2";
  return "T1";
}

function machineSandboxTier(machine: MachineCapability): SandboxTier | null {
  const s = machine.sandbox;

  // The privileged broker is a trusted control-plane component that launches
  // a non-root, read-only, cap-dropped worker container. Rootless Docker is not
  // required for this verified T1 path. T2 remains unavailable here.
  if (s.container_runtime === "docker-broker") {
    return s.cgroups && s.seccomp ? "T1" : null;
  }

  // Standard GitHub-hosted Linux jobs execute on fresh GitHub-managed VMs.
  // For public/no-secret worker tasks, the ephemeral VM is the T1 isolation
  // boundary; network_policy means the trusted workflow exposes no target
  // write credential to the model process.
  if (s.container_runtime === "github-actions-docker") {
    return s.network_policy && s.cgroups && s.seccomp ? "T1" : null;
  }

  if (!s.landlock) return null;
  if (!(s.rootless_container && s.cgroups && s.seccomp)) return "T0";
  return "T1";
}

export function evaluateMachineEligibility(
  task: TaskSpec,
  passport: RepoPassport,
  machine: MachineCapability,
  policy: SchedulerAdmissionPolicy = DEFAULT_ADMISSION_POLICY,
): EligibilityResult {
  const reasons: EligibilityReason[] = [];
  const requiredSandboxTier = defaultSandboxTier(task);

  if (!machine.online) {
    reasons.push({ code: "MACHINE_OFFLINE", detail: "Machine is not currently online." });
  }

  const activeSlots = machine.active_slots ?? 0;
  if (activeSlots >= machine.max_slots) {
    reasons.push({
      code: "NO_SLOT_CAPACITY",
      detail: "Machine has no free execution slots (" + activeSlots + "/" + machine.max_slots + ").",
    });
  }

  const diskUsedPercent = machine.disk_used_percent;
  const diskPressureByPercent =
    diskUsedPercent !== undefined && diskUsedPercent >= policy.diskBlockPercent;
  const diskPressureByFree = machine.disk_free_bytes < policy.minFreeDiskBytes;
  if (diskPressureByPercent || diskPressureByFree) {
    const usedText =
      diskUsedPercent === undefined ? "unknown" : diskUsedPercent.toFixed(2) + "%";
    reasons.push({
      code: "DISK_PRESSURE",
      detail:
        "Disk admission gate failed: used=" +
        usedText +
        ", free=" +
        machine.disk_free_bytes +
        " bytes, limits: used<" +
        policy.diskBlockPercent +
        "% and free>=" +
        policy.minFreeDiskBytes +
        " bytes.",
    });
  }

  if (riskRank[task.risk_class] > riskRank[machine.trust_ceiling]) {
    reasons.push({
      code: "RISK_EXCEEDS_MACHINE_TRUST",
      detail: "Task risk " + task.risk_class + " exceeds machine trust ceiling " + machine.trust_ceiling + ".",
    });
  }

  if (!passport.network_profiles.includes(task.network_profile)) {
    reasons.push({
      code: "NETWORK_PROFILE_NOT_ALLOWED_BY_REPO",
      detail: "Repo Passport does not allow network profile " + task.network_profile + ".",
    });
  }

  if (!machine.network_profiles.includes(task.network_profile)) {
    reasons.push({
      code: "NETWORK_PROFILE_UNAVAILABLE",
      detail: "Machine cannot enforce network profile " + task.network_profile + ".",
    });
  }

  if (
    task.network_profile !== "none" &&
    !machine.sandbox.network_policy &&
    sandboxRank[requiredSandboxTier] >= sandboxRank.T1
  ) {
    reasons.push({
      code: "NETWORK_POLICY_UNAVAILABLE",
      detail: "Task requires controlled network access but machine lacks enforceable network policy.",
    });
  }

  if (!machine.tool_profiles.includes(task.tool_profile)) {
    reasons.push({
      code: "TOOL_PROFILE_UNAVAILABLE",
      detail: "Machine does not provide tool profile " + task.tool_profile + ".",
    });
  }

  if (!passport.allowed_model_classes.includes(task.model_requirements.class)) {
    reasons.push({
      code: "MODEL_CLASS_NOT_ALLOWED_BY_REPO",
      detail: "Repo Passport does not allow model class " + task.model_requirements.class + ".",
    });
  }

  if (!machine.model_classes.includes(task.model_requirements.class)) {
    reasons.push({
      code: "MODEL_CLASS_UNAVAILABLE",
      detail: "Machine has no healthy route for model class " + task.model_requirements.class + ".",
    });
  }

  const machineTier = machineSandboxTier(machine);
  if (!machineTier || sandboxRank[machineTier] < sandboxRank[requiredSandboxTier]) {
    reasons.push({
      code: "SANDBOX_TIER_UNAVAILABLE",
      detail:
        "Machine sandbox tier " +
        (machineTier ?? "NONE") +
        " does not satisfy " +
        requiredSandboxTier +
        ".",
    });
  }

  const taskAllowed = new Set(task.harness_requirements.allowed_adapters ?? passport.allowed_harnesses);
  const eligibleHarnesses: string[] = [];
  const seenAllowed = new Set<string>();

  for (const harness of machine.harnesses) {
    if (!taskAllowed.has(harness.adapter)) continue;
    seenAllowed.add(harness.adapter);

    if (!passport.allowed_harnesses.includes(harness.adapter)) {
      reasons.push({
        code: "HARNESS_NOT_ALLOWED_BY_REPO",
        detail: "Harness " + harness.adapter + " is disallowed by Repo Passport.",
      });
      continue;
    }

    if (!harness.healthy) {
      reasons.push({
        code: "HARNESS_UNHEALTHY",
        detail: "Harness " + harness.adapter + "@" + harness.version + " is not healthy.",
      });
      continue;
    }

    const missing = task.harness_requirements.required_capabilities.filter(
      (capability) => !harness.capabilities.includes(capability),
    );
    if (missing.length > 0) {
      reasons.push({
        code: "HARNESS_CAPABILITY_MISSING",
        detail: "Harness " + harness.adapter + " lacks capabilities: " + missing.join(", ") + ".",
      });
      continue;
    }

    eligibleHarnesses.push(harness.adapter);
  }

  if (eligibleHarnesses.length === 0 && seenAllowed.size === 0) {
    reasons.push({
      code: "HARNESS_UNAVAILABLE",
      detail: "No machine harness matches the task and Repo Passport allowlists.",
    });
  }

  const hardFailure = reasons.length > 0 || eligibleHarnesses.length === 0;
  const freeRatio = Math.max(0, machine.max_slots - activeSlots) / machine.max_slots;
  const score = hardFailure ? 0 : Math.round(60 + freeRatio * 40);

  return {
    eligible: !hardFailure,
    reasons,
    eligibleHarnesses: [...new Set(eligibleHarnesses)].sort(),
    requiredSandboxTier,
    score,
  };
}

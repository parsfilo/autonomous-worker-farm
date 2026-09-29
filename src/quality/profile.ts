import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import type {
  QualityProfile,
  RepoPassport,
  TaskSpec,
  ValidationPlan,
} from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

const COMMAND_GATES = [
  "format",
  "lint",
  "typecheck",
  "build",
  "tests",
  "secret_scan",
] as const;
type CommandGate = (typeof COMMAND_GATES)[number];

const SCANNER_GATES = ["semgrep", "codacy", "sonar"] as const;
type ScannerGate = (typeof SCANNER_GATES)[number];

function argvEqual(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function requireAllowedRepoCommand(
  gate: CommandGate,
  argv: string[],
  passport: RepoPassport,
): void {
  const allowlist =
    gate === "build"
      ? passport.allowed_build_commands
      : gate === "tests"
        ? passport.allowed_test_commands
        : null;
  if (allowlist === null) return;
  if (!allowlist.some((allowed) => argvEqual(allowed, argv))) {
    throw new ControllerError(
      "QUALITY_COMMAND_NOT_ALLOWED",
      "Trusted quality profile command is not allowed by the Repo Passport",
      { gate, argv },
    );
  }
}

export function validateQualityProfile(
  input: unknown,
  contracts = new ContractRegistry(),
): QualityProfile {
  const profile = contracts.validate<QualityProfile>("quality-profile", input);
  const seen = new Set<string>();
  for (const command of profile.commands) {
    if (seen.has(command.gate)) {
      throw new ControllerError(
        "QUALITY_PROFILE_INVALID",
        "Quality profile contains duplicate command gate",
        { gate: command.gate },
      );
    }
    seen.add(command.gate);
  }
  return profile;
}

export function loadQualityProfile(
  path: string,
  contracts = new ContractRegistry(),
): QualityProfile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new ControllerError(
      "QUALITY_PROFILE_LOAD_FAILED",
      "Could not read trusted quality profile",
      { path, cause: error instanceof Error ? error.message : String(error) },
    );
  }
  return validateQualityProfile(parsed, contracts);
}


export function loadTrustedQualityProfile(root: string, profileId: string): QualityProfile {
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(profileId)) {
    throw new ControllerError("QUALITY_PROFILE_PATH_INVALID", "Quality profile id is invalid");
  }
  const trustedRoot = realpathSync(resolve(root));
  const candidate = realpathSync(join(trustedRoot, profileId + ".json"));
  if (candidate === trustedRoot || !candidate.startsWith(trustedRoot + "/")) {
    throw new ControllerError("QUALITY_PROFILE_PATH_INVALID", "Trusted quality profile escaped its root");
  }
  const info = lstatSync(candidate);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new ControllerError("QUALITY_PROFILE_PATH_INVALID", "Trusted quality profile must be a real file");
  }
  return loadQualityProfile(candidate);
}

function requestedCommandGates(task: TaskSpec, passport: RepoPassport): Set<CommandGate> {
  const requested = new Set<CommandGate>();
  for (const gate of COMMAND_GATES) {
    if (passport.quality[gate].required) requested.add(gate);
  }
  if (task.evidence_requirements.includes("tests")) requested.add("tests");
  return requested;
}

function requestedScannerGates(task: TaskSpec, passport: RepoPassport): Set<ScannerGate> {
  const requested = new Set<ScannerGate>();
  for (const gate of SCANNER_GATES) {
    if (passport.quality[gate].required || task.evidence_requirements.includes(gate)) {
      requested.add(gate);
    }
  }
  return requested;
}

export function buildValidationPlanFromQualityProfile(input: {
  task: TaskSpec;
  passport: RepoPassport;
  candidateHash: string;
  validationWorkspace: string;
  profile: QualityProfile;
  contracts?: ContractRegistry;
}): ValidationPlan {
  const contracts = input.contracts ?? new ContractRegistry();
  const task = contracts.validate<TaskSpec>("task-spec", input.task);
  const passport = contracts.validate<RepoPassport>("repo-passport", input.passport);
  const profile = validateQualityProfile(input.profile, contracts);

  if (task.repo_id !== passport.repo_id) {
    throw new ControllerError("QUALITY_PLAN_REPO_MISMATCH", "Task and Repo Passport repo_id differ");
  }
  if (task.quality_profile !== profile.profile_id) {
    throw new ControllerError(
      "QUALITY_PROFILE_MISMATCH",
      "Task quality_profile does not match trusted quality profile",
      { taskProfile: task.quality_profile, trustedProfile: profile.profile_id },
    );
  }
  if (!/^[0-9a-f]{64}$/.test(input.candidateHash)) {
    throw new ControllerError("CANDIDATE_HASH_INVALID", "Validation plan requires candidate SHA-256");
  }
  if (!input.validationWorkspace.startsWith("/")) {
    throw new ControllerError(
      "VALIDATION_WORKSPACE_INVALID",
      "Validation workspace must be an absolute path",
    );
  }

  const profileCommands = new Map(profile.commands.map((entry) => [entry.gate, entry]));
  const requestedCommands = requestedCommandGates(task, passport);
  const commands: ValidationPlan["commands"] = [];

  for (const gate of COMMAND_GATES) {
    if (!requestedCommands.has(gate)) continue;
    const configured = profileCommands.get(gate);
    if (!configured) {
      throw new ControllerError(
        "QUALITY_PROFILE_GATE_MISSING",
        "Required/evidence command gate is missing from trusted quality profile",
        { gate, profile: profile.profile_id },
      );
    }
    requireAllowedRepoCommand(gate, configured.argv, passport);
    commands.push({
      name: gate,
      argv: [...configured.argv],
      required: passport.quality[gate].required,
      timeout_seconds: configured.timeout_seconds,
    });
  }

  const requestedScanners = requestedScannerGates(task, passport);
  const scannerProfiles: ValidationPlan["scanner_profiles"] = {
    semgrep: null,
    codacy: null,
    sonar: null,
  };
  for (const gate of SCANNER_GATES) {
    if (!requestedScanners.has(gate)) continue;
    const configured = profile.scanner_profiles[gate];
    if (!configured) {
      throw new ControllerError(
        "QUALITY_PROFILE_GATE_MISSING",
        "Required/evidence scanner gate is missing from trusted quality profile",
        { gate, profile: profile.profile_id },
      );
    }
    scannerProfiles[gate] = configured;
  }

  if (
    profile.network_profile === "none" &&
    (requestedScanners.has("codacy") || requestedScanners.has("sonar"))
  ) {
    throw new ControllerError(
      "QUALITY_NETWORK_PROFILE_INSUFFICIENT",
      "Codacy/Sonar gate requires a separately approved quality-services network profile",
      { profile: profile.profile_id },
    );
  }

  const identity = {
    task_id: task.task_id,
    candidate_hash: input.candidateHash,
    base_sha: task.base_sha,
    quality_profile: profile.profile_id,
    quality_profile_revision: profile.revision,
    commands,
    scanner_profiles: scannerProfiles,
    network_profile: profile.network_profile,
    timeout_seconds: profile.timeout_seconds,
  };
  const plan: ValidationPlan = {
    schema_version: "1.0",
    plan_id: "validation-" + sha256CanonicalJson(identity).slice(0, 40),
    task_id: task.task_id,
    candidate_hash: input.candidateHash,
    base_sha: task.base_sha,
    validation_workspace: input.validationWorkspace,
    commands,
    scanner_profiles: scannerProfiles,
    network_profile: profile.network_profile,
    timeout_seconds: profile.timeout_seconds,
  };
  return contracts.validate<ValidationPlan>("validation-plan", plan);
}

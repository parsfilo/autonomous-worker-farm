import type {
  GateEvidence,
  RepoPassport,
  ResultManifest,
  SandboxTier,
  TaskSpec,
} from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256Bytes, buildCandidateDescriptor, computeCandidateHash } from "./candidate.js";
import { ControllerError } from "../lib/errors.js";
import { verifyChangedPathPolicy } from "./path-policy.js";

const tierRank: Record<SandboxTier, number> = { T0: 0, T1: 1, T2: 2 };

export interface WorkerManifestVerificationReport {
  accepted: true;
  candidateHash: string;
  normalizedChangedFiles: string[];
  protectedPathsTouched: string[];
  verifiedGateNames: string[];
}

function requireGate(name: string, evidence: GateEvidence): void {
  if (evidence.status !== "PASS") {
    throw new ControllerError("REQUIRED_GATE_FAILED", "Required gate did not pass: " + name, {
      gate: name,
      status: evidence.status,
      exitCode: evidence.exit_code ?? null,
    });
  }
}

function requireEqual(label: string, expected: string, actual: string): void {
  if (expected !== actual) {
    throw new ControllerError("RESULT_MANIFEST_MISMATCH", label + " mismatch", {
      expected,
      actual,
    });
  }
}

function minimumSandboxTier(task: TaskSpec): SandboxTier {
  if (task.harness_requirements.minimum_sandbox_tier) return task.harness_requirements.minimum_sandbox_tier;
  if (task.risk_class === "LOW" && task.write_scope.length === 0) return "T0";
  if (task.risk_class === "PROTECTED") return "T2";
  return "T1";
}

export function verifyWorkerManifest(
  task: TaskSpec,
  passport: RepoPassport,
  input: unknown,
  patchBytes?: Uint8Array,
  options: { enforceRequiredQuality?: boolean } = {},
  contracts = new ContractRegistry(),
): WorkerManifestVerificationReport {
  const manifest = contracts.validate<ResultManifest>("result-manifest", input);

  requireEqual("task_id", task.task_id, manifest.task_id);
  requireEqual("base_sha", task.base_sha, manifest.base_sha);
  requireEqual("repo_passport_hash", task.repo_passport_hash, manifest.repo_passport_hash);
  requireEqual("context_snapshot_hash", task.context_snapshot_hash, manifest.context_snapshot_hash);

  if (manifest.status !== "SUCCEEDED") {
    throw new ControllerError("WORKER_RESULT_NOT_SUCCESSFUL", "Only SUCCEEDED manifests can form candidates", {
      status: manifest.status,
    });
  }

  if (!manifest.sandbox.attested) {
    throw new ControllerError("SANDBOX_NOT_ATTESTED", "Worker manifest does not carry a positive sandbox attestation");
  }

  const requiredTier = minimumSandboxTier(task);
  if (tierRank[manifest.sandbox.tier] < tierRank[requiredTier]) {
    throw new ControllerError("SANDBOX_TIER_INSUFFICIENT", "Worker sandbox tier is below TaskSpec requirement", {
      requiredTier,
      actualTier: manifest.sandbox.tier,
    });
  }

  if (patchBytes) {
    if (!manifest.patch_sha256) {
      throw new ControllerError("PATCH_HASH_MISSING", "Patch bytes were supplied but manifest patch_sha256 is absent");
    }
    const actualPatchHash = sha256Bytes(patchBytes);
    requireEqual("patch_sha256", manifest.patch_sha256, actualPatchHash);
  }

  const pathReport = verifyChangedPathPolicy(task, passport, manifest.changed_files);
  const descriptor = buildCandidateDescriptor(task, {
    ...manifest,
    changed_files: pathReport.normalizedPaths,
  });
  contracts.validate("candidate-descriptor", descriptor);

  const candidateHash = computeCandidateHash(descriptor);
  requireEqual("candidate_hash", candidateHash, manifest.candidate_hash);

  const verifiedGateNames: string[] = [];
  const checkMap: Record<string, GateEvidence> = {
    format: manifest.checks.format,
    lint: manifest.checks.lint,
    typecheck: manifest.checks.typecheck,
    build: manifest.checks.build,
    secret_scan: manifest.checks.secret_scan,
    semgrep: manifest.quality.semgrep,
    codacy: manifest.quality.codacy,
    sonar: manifest.quality.sonar,
  };

  if (options.enforceRequiredQuality !== false) {
  for (const [name, requirement] of Object.entries(passport.quality)) {
    if (!requirement.required) continue;
    if (name === "tests") {
      if (manifest.tests.length === 0) {
        throw new ControllerError("REQUIRED_GATE_MISSING", "Required tests evidence is empty");
      }
      manifest.tests.forEach((evidence, index) => requireGate("tests[" + index + "]", evidence));
      verifiedGateNames.push("tests");
      continue;
    }

    const evidence = checkMap[name];
    if (!evidence) {
      throw new ControllerError("REQUIRED_GATE_MISSING", "Required gate evidence is missing: " + name);
    }
    requireGate(name, evidence);
    verifiedGateNames.push(name);
  }
  }

  const policyDenials = manifest.policy_events.filter((event) => {
    if (!event || typeof event !== "object") return false;
    return (event as Record<string, unknown>).decision === "deny";
  });
  if (policyDenials.length > 0) {
    throw new ControllerError(
      "POLICY_DENIAL_RECORDED",
      "Candidate attempt recorded denied policy actions and must not be promoted automatically",
      { count: policyDenials.length },
    );
  }

  return {
    accepted: true,
    candidateHash,
    normalizedChangedFiles: pathReport.normalizedPaths,
    protectedPathsTouched: pathReport.protectedPathsTouched,
    verifiedGateNames: verifiedGateNames.sort(),
  };
}

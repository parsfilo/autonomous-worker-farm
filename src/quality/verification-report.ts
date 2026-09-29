import type {
  ValidationPlan,
  VerificationCommandResult,
  VerificationGate,
  VerificationReport,
} from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

export interface VerificationReportInput {
  startedAt: string;
  endedAt: string;
  commandResults: VerificationCommandResult[];
  gates: Record<string, VerificationGate>;
  verifier: {
    machine_id: string;
    build: string;
  };
}

export function computeVerificationReportHash(
  report: Omit<VerificationReport, "report_hash">,
): string {
  return sha256CanonicalJson(report);
}


function sameArgv(expected: string[], actual: string[]): boolean {
  return (
    expected.length === actual.length &&
    expected.every((value, index) => value === actual[index])
  );
}

function validateCoverage(
  plan: ValidationPlan,
  commandResults: VerificationCommandResult[],
  gates: Record<string, VerificationGate>,
): void {
  const plannedByName = new Map<string, ValidationPlan["commands"][number]>();
  for (const command of plan.commands) {
    if (plannedByName.has(command.name)) {
      throw new ControllerError(
        "VALIDATION_PLAN_AMBIGUOUS",
        "Validation plan contains duplicate command names",
        { command: command.name },
      );
    }
    plannedByName.set(command.name, command);
  }

  const resultByName = new Map<string, VerificationCommandResult>();
  for (const result of commandResults) {
    if (resultByName.has(result.name)) {
      throw new ControllerError(
        "VERIFICATION_REPORT_COVERAGE",
        "Verification report contains duplicate command results",
        { command: result.name },
      );
    }
    const planned = plannedByName.get(result.name);
    if (!planned) {
      throw new ControllerError(
        "VERIFICATION_REPORT_COVERAGE",
        "Verification report contains an unplanned command result",
        { command: result.name },
      );
    }
    if (!sameArgv(planned.argv, result.argv)) {
      throw new ControllerError(
        "VERIFICATION_REPORT_COVERAGE",
        "Verification command argv does not match the trusted validation plan",
        { command: result.name, expected: planned.argv, actual: result.argv },
      );
    }
    resultByName.set(result.name, result);
  }

  for (const command of plan.commands) {
    if (!resultByName.has(command.name)) {
      throw new ControllerError(
        "VERIFICATION_REPORT_COVERAGE",
        "Verification report omitted a planned command",
        { command: command.name, required: command.required },
      );
    }
  }

  const expectedGates = new Set(
    Object.entries(plan.scanner_profiles)
      .filter(([, profile]) => profile !== null)
      .map(([name]) => name),
  );
  const actualGates = new Set(Object.keys(gates));

  for (const expected of expectedGates) {
    if (!actualGates.has(expected)) {
      throw new ControllerError(
        "VERIFICATION_REPORT_COVERAGE",
        "Verification report omitted a planned scanner gate",
        { gate: expected },
      );
    }
  }
  for (const actual of actualGates) {
    if (!expectedGates.has(actual)) {
      throw new ControllerError(
        "VERIFICATION_REPORT_COVERAGE",
        "Verification report contains an unplanned scanner gate",
        { gate: actual },
      );
    }
  }
}

function deriveStatus(
  plan: ValidationPlan,
  commandResults: VerificationCommandResult[],
  gates: Record<string, VerificationGate>,
): VerificationReport["status"] {
  const gateValues = Object.values(gates);
  const hasError = gateValues.some((gate) => gate.status === "ERROR");
  if (hasError) return "ERROR";

  const commandByName = new Map(commandResults.map((result) => [result.name, result]));
  const requiredCommandFailed = plan.commands.some(
    (command) => command.required && commandByName.get(command.name)?.exit_code !== 0,
  );
  const gateFailed = gateValues.some((gate) => gate.status === "FAIL");
  return requiredCommandFailed || gateFailed ? "FAIL" : "PASS";
}

export function buildVerificationReport(
  planInput: unknown,
  input: VerificationReportInput,
  contracts = new ContractRegistry(),
): VerificationReport {
  const plan = contracts.validate<ValidationPlan>("validation-plan", planInput);

  validateCoverage(plan, input.commandResults, input.gates);
  const status = deriveStatus(plan, input.commandResults, input.gates);

  const unsigned: Omit<VerificationReport, "report_hash"> = {
    schema_version: "1.0",
    plan_id: plan.plan_id,
    task_id: plan.task_id,
    candidate_hash: plan.candidate_hash,
    base_sha: plan.base_sha,
    status,
    started_at: input.startedAt,
    ended_at: input.endedAt,
    command_results: input.commandResults,
    gates: input.gates,
    verifier: input.verifier,
  };

  const report: VerificationReport = {
    ...unsigned,
    report_hash: computeVerificationReportHash(unsigned),
  };

  contracts.validate<VerificationReport>("verification-report", report);
  return report;
}

export function verifyVerificationReport(
  planInput: unknown,
  reportInput: unknown,
  contracts = new ContractRegistry(),
): VerificationReport {
  const plan = contracts.validate<ValidationPlan>("validation-plan", planInput);
  const report = contracts.validate<VerificationReport>("verification-report", reportInput);

  if (plan.plan_id !== report.plan_id) {
    throw new ControllerError("VERIFICATION_REPORT_MISMATCH", "plan_id mismatch");
  }
  if (plan.task_id !== report.task_id) {
    throw new ControllerError("VERIFICATION_REPORT_MISMATCH", "task_id mismatch");
  }
  if (plan.candidate_hash !== report.candidate_hash) {
    throw new ControllerError("VERIFICATION_REPORT_MISMATCH", "candidate_hash mismatch");
  }
  if (plan.base_sha !== report.base_sha) {
    throw new ControllerError("VERIFICATION_REPORT_MISMATCH", "base_sha mismatch");
  }

  validateCoverage(plan, report.command_results, report.gates);
  const expectedStatus = deriveStatus(plan, report.command_results, report.gates);
  if (report.status !== expectedStatus) {
    throw new ControllerError(
      "VERIFICATION_REPORT_STATUS_MISMATCH",
      "Verification report status does not match trusted plan/results",
      { expected: expectedStatus, actual: report.status },
    );
  }

  const { report_hash: _reportedHash, ...unsigned } = report;
  const expectedHash = computeVerificationReportHash(unsigned);
  if (expectedHash !== report.report_hash) {
    throw new ControllerError("VERIFICATION_REPORT_HASH_MISMATCH", "Verification report hash mismatch", {
      expected: expectedHash,
      actual: report.report_hash,
    });
  }

  return report;
}

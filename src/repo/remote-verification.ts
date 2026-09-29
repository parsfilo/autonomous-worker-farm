import type { RemoteVerificationReport } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

function reportHash(
  report: Omit<RemoteVerificationReport, "report_hash"> | RemoteVerificationReport,
): string {
  const { report_hash: _ignored, ...body } = report as RemoteVerificationReport;
  return sha256CanonicalJson(body);
}

function assertSemantics(report: RemoteVerificationReport): void {
  const checksOnExpectedHead = report.remote_checks.every(
    (check) => check.head_sha === report.expected_commit_sha,
  );
  const allChecksPass = report.remote_checks.every((check) => check.status === "PASS");
  const anyCheckFails = report.remote_checks.some(
    (check) => check.status === "FAIL" || check.status === "ERROR",
  );

  if (report.status === "PASS") {
    if (
      report.observed_base_sha !== report.expected_base_sha ||
      report.observed_pr_head_sha !== report.expected_commit_sha ||
      report.pr_state !== "OPEN" ||
      !checksOnExpectedHead ||
      !allChecksPass
    ) {
      throw new ControllerError(
        "REMOTE_VERIFICATION_INCONSISTENT",
        "PASS remote verification is not exact-SHA/base/check consistent",
      );
    }
  }
  if (report.status === "BASE_DRIFT" && report.observed_base_sha === report.expected_base_sha) {
    throw new ControllerError("REMOTE_VERIFICATION_INCONSISTENT", "BASE_DRIFT requires observed base SHA drift");
  }
  if (
    report.status === "HEAD_MISMATCH" &&
    report.observed_pr_head_sha === report.expected_commit_sha
  ) {
    throw new ControllerError("REMOTE_VERIFICATION_INCONSISTENT", "HEAD_MISMATCH requires PR head SHA mismatch");
  }
  if (report.status === "QUALITY_FAILED" && !anyCheckFails) {
    throw new ControllerError("REMOTE_VERIFICATION_INCONSISTENT", "QUALITY_FAILED requires a failed/error remote check");
  }
}

export function finalizeRemoteVerificationReport(
  body: Omit<RemoteVerificationReport, "report_hash">,
  contracts = new ContractRegistry(),
): RemoteVerificationReport {
  const report: RemoteVerificationReport = {
    ...body,
    report_hash: reportHash(body),
  };
  contracts.validate<RemoteVerificationReport>("remote-verification-report", report);
  assertSemantics(report);
  return report;
}

export function verifyRemoteVerificationReport(
  report: RemoteVerificationReport,
  contracts = new ContractRegistry(),
): RemoteVerificationReport {
  contracts.validate<RemoteVerificationReport>("remote-verification-report", report);
  if (report.report_hash !== reportHash(report)) {
    throw new ControllerError("REMOTE_VERIFICATION_REPORT_HASH_MISMATCH", "Remote verification report hash mismatch");
  }
  assertSemantics(report);
  return report;
}

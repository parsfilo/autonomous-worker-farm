import type { PostMergeVerificationReport } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

function hashReport(
  report:
    | Omit<PostMergeVerificationReport, "report_hash">
    | PostMergeVerificationReport,
): string {
  const { report_hash: _ignored, ...body } =
    report as PostMergeVerificationReport;
  return sha256CanonicalJson(body);
}

function assertSemantics(report: PostMergeVerificationReport): void {
  const required = new Set(report.required_checks);
  const byName = new Map(report.observed_checks.map((check) => [check.name, check]));
  const missing = [...required].filter((name) => !byName.has(name));
  const wrongSha = report.observed_checks.filter(
    (check) => check.head_sha !== report.merge_sha,
  );
  const requiredObserved = [...required]
    .map((name) => byName.get(name))
    .filter((value): value is NonNullable<typeof value> => Boolean(value));
  const failures = requiredObserved.filter(
    (check) => check.status === "FAIL" || check.status === "ERROR",
  );
  const pending = requiredObserved.filter((check) => check.status === "PENDING");

  if (wrongSha.length > 0) {
    throw new ControllerError(
      "POST_MERGE_VERIFICATION_SHA_MISMATCH",
      "Post-merge observations must be bound to the exact merge SHA",
    );
  }
  if (report.status === "PASS") {
    if (missing.length > 0 || failures.length > 0 || pending.length > 0) {
      throw new ControllerError(
        "POST_MERGE_VERIFICATION_INCONSISTENT",
        "PASS requires every configured post-merge check to be observed PASS",
        { missing, failures: failures.length, pending: pending.length },
      );
    }
  }
  if (report.status === "PENDING" && missing.length === 0 && pending.length === 0) {
    throw new ControllerError(
      "POST_MERGE_VERIFICATION_INCONSISTENT",
      "PENDING requires a missing or pending required check",
    );
  }
  if (report.status === "QUALITY_FAILED" && failures.length === 0) {
    throw new ControllerError(
      "POST_MERGE_VERIFICATION_INCONSISTENT",
      "QUALITY_FAILED requires a failed/error required check",
    );
  }
}

export function finalizePostMergeVerificationReport(
  body: Omit<PostMergeVerificationReport, "report_hash">,
  contracts = new ContractRegistry(),
): PostMergeVerificationReport {
  const report: PostMergeVerificationReport = {
    ...body,
    report_hash: hashReport(body),
  };
  contracts.validate<PostMergeVerificationReport>(
    "post-merge-verification-report",
    report,
  );
  assertSemantics(report);
  return report;
}

export function verifyPostMergeVerificationReport(
  report: PostMergeVerificationReport,
  contracts = new ContractRegistry(),
): PostMergeVerificationReport {
  contracts.validate<PostMergeVerificationReport>(
    "post-merge-verification-report",
    report,
  );
  if (report.report_hash !== hashReport(report)) {
    throw new ControllerError(
      "POST_MERGE_VERIFICATION_REPORT_HASH_MISMATCH",
      "Post-merge verification report hash mismatch",
    );
  }
  assertSemantics(report);
  return report;
}

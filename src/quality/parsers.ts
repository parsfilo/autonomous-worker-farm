import type { VerificationGate } from "../../contracts/types.js";
import { sha256Bytes } from "../evidence/candidate.js";
import { ControllerError } from "../lib/errors.js";

function parseJson(bytes: Uint8Array, label: string): Record<string, unknown> {
  try {
    const value = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("top-level value is not an object");
    }
    return value as Record<string, unknown>;
  } catch (error) {
    throw new ControllerError("QUALITY_REPORT_INVALID_JSON", label + " report is invalid JSON", {
      cause: error instanceof Error ? error.message : String(error),
    });
  }
}

function arrayField(record: Record<string, unknown>, key: string): unknown[] {
  const value = record[key];
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ControllerError("QUALITY_REPORT_INVALID_SHAPE", key + " must be an array");
  }
  return value;
}

export function evaluateSemgrepJson(bytes: Uint8Array): VerificationGate {
  const report = parseJson(bytes, "Semgrep");
  const results = arrayField(report, "results");
  const errors = arrayField(report, "errors");
  const evidenceSha256 = sha256Bytes(bytes);

  if (errors.length > 0) {
    return {
      status: "ERROR",
      evidence_sha256: evidenceSha256,
      details: { findings: results.length, errors: errors.length },
    };
  }

  return {
    status: results.length === 0 ? "PASS" : "FAIL",
    evidence_sha256: evidenceSha256,
    details: { findings: results.length, errors: 0 },
  };
}

export function evaluateCodacyJson(bytes: Uint8Array): VerificationGate {
  const report = parseJson(bytes, "Codacy");
  const issues = arrayField(report, "issues");
  const errors = arrayField(report, "errors");
  const capabilityRaw = report.capability;
  let unavailable = 0;

  if (capabilityRaw !== undefined) {
    if (!capabilityRaw || typeof capabilityRaw !== "object" || Array.isArray(capabilityRaw)) {
      throw new ControllerError("QUALITY_REPORT_INVALID_SHAPE", "Codacy capability must be an object");
    }
    const capability = capabilityRaw as Record<string, unknown>;
    unavailable = arrayField(capability, "unavailable").length;
  }

  const evidenceSha256 = sha256Bytes(bytes);
  if (errors.length > 0 || unavailable > 0) {
    return {
      status: "ERROR",
      evidence_sha256: evidenceSha256,
      details: { issues: issues.length, errors: errors.length, unavailable },
    };
  }

  return {
    status: issues.length === 0 ? "PASS" : "FAIL",
    evidence_sha256: evidenceSha256,
    details: { issues: issues.length, errors: 0, unavailable: 0 },
  };
}

export function evaluateSonarQualityGateJson(bytes: Uint8Array): VerificationGate {
  const report = parseJson(bytes, "Sonar");
  const projectStatusRaw = report.projectStatus;
  if (!projectStatusRaw || typeof projectStatusRaw !== "object" || Array.isArray(projectStatusRaw)) {
    throw new ControllerError(
      "QUALITY_REPORT_INVALID_SHAPE",
      "Sonar report must contain projectStatus object",
    );
  }

  const projectStatus = projectStatusRaw as Record<string, unknown>;
  const status = projectStatus.status;
  if (typeof status !== "string") {
    throw new ControllerError(
      "QUALITY_REPORT_INVALID_SHAPE",
      "Sonar projectStatus.status must be a string",
    );
  }

  const evidenceSha256 = sha256Bytes(bytes);
  if (status === "OK") {
    return {
      status: "PASS",
      evidence_sha256: evidenceSha256,
      details: { sonarStatus: status },
    };
  }
  if (status === "ERROR") {
    return {
      status: "FAIL",
      evidence_sha256: evidenceSha256,
      details: { sonarStatus: status },
    };
  }

  return {
    status: "ERROR",
    evidence_sha256: evidenceSha256,
    details: { sonarStatus: status },
  };
}

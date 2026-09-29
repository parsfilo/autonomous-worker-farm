import { createHash } from "node:crypto";
import type { IndependentReviewFinding, IndependentReviewReport } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

export interface ParsedOpenCodeReview {
  verdict: "PASS" | "BLOCK";
  findings: IndependentReviewFinding[];
  summary: string;
}

function parseFinding(value: unknown): IndependentReviewFinding {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review finding must be an object");
  }
  const item = value as Record<string, unknown>;
  const keys = Object.keys(item).sort();
  const expected = ["code", "line", "path", "severity", "summary"];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review finding has unexpected fields");
  }
  if (item.severity !== "BLOCKING" && item.severity !== "NON_BLOCKING") {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review finding severity is invalid");
  }
  if (typeof item.code !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(item.code)) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review finding code is invalid");
  }
  if (typeof item.summary !== "string" || item.summary.length < 1 || item.summary.length > 2000) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review finding summary is invalid");
  }
  if (item.path !== null && (typeof item.path !== "string" || item.path.length < 1 || item.path.length > 1024)) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review finding path is invalid");
  }
  if (item.line !== null && (!Number.isInteger(item.line) || Number(item.line) < 1 || Number(item.line) > 10000000)) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review finding line is invalid");
  }
  return {
    severity: item.severity,
    code: item.code,
    summary: item.summary,
    path: item.path as string | null,
    line: item.line === null ? null : Number(item.line),
  };
}

export function parseOpenCodeReviewOutput(stdout: string): ParsedOpenCodeReview {
  const texts: string[] = [];
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let event: unknown;
    try {
      event = JSON.parse(trimmed);
    } catch {
      throw new ControllerError("REVIEW_OUTPUT_INVALID", "OpenCode review stdout contains non-JSON event output");
    }
    if (!event || typeof event !== "object" || Array.isArray(event)) continue;
    const record = event as Record<string, unknown>;
    if (record.type !== "text") continue;
    const part = record.part;
    if (!part || typeof part !== "object" || Array.isArray(part) || typeof (part as Record<string, unknown>).text !== "string") {
      throw new ControllerError("REVIEW_OUTPUT_INVALID", "OpenCode text event is malformed");
    }
    texts.push((part as Record<string, unknown>).text as string);
  }

  const raw = texts.join("").trim();
  if (!raw) throw new ControllerError("REVIEW_OUTPUT_INVALID", "OpenCode review returned no text payload");

  const parseObject = (value: string): unknown | null => {
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
    } catch {
      return null;
    }
  };

  let parsed: unknown = parseObject(raw);
  if (!parsed) {
    const candidates: unknown[] = [];
    let start = -1;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let index = 0; index < raw.length; index += 1) {
      const char = raw[index]!;
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (char === "\\") {
          escaped = true;
        } else if (char === '"') {
          inString = false;
        }
        continue;
      }
      if (char === '"') {
        inString = true;
        continue;
      }
      if (char === "{") {
        if (depth === 0) start = index;
        depth += 1;
        continue;
      }
      if (char === "}" && depth > 0) {
        depth -= 1;
        if (depth === 0 && start >= 0) {
          const candidate = parseObject(raw.slice(start, index + 1));
          if (candidate) candidates.push(candidate);
          start = -1;
        }
      }
    }
    if (candidates.length === 1) {
      parsed = candidates[0];
    } else {
      throw new ControllerError(
        "REVIEW_OUTPUT_INVALID",
        "Review text payload must contain exactly one unambiguous JSON object",
        { excerpt: raw.slice(0, 512), candidateObjects: candidates.length },
      );
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review payload must be an object");
  }
  const value = parsed as Record<string, unknown>;
  const keys = Object.keys(value).sort();
  const expected = ["findings", "summary", "verdict"];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review payload has unexpected fields");
  }
  if (value.verdict !== "PASS" && value.verdict !== "BLOCK") {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review verdict is invalid");
  }
  if (!Array.isArray(value.findings) || value.findings.length > 100) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review findings must be an array");
  }
  if (typeof value.summary !== "string" || value.summary.length < 1 || value.summary.length > 4000) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review summary is invalid");
  }
  const findings = value.findings.map(parseFinding);
  const hasBlocking = findings.some((finding) => finding.severity === "BLOCKING");
  if ((value.verdict === "PASS" && hasBlocking) || (value.verdict === "BLOCK" && !hasBlocking)) {
    throw new ControllerError("REVIEW_OUTPUT_INVALID", "Review verdict is inconsistent with blocking findings");
  }
  return { verdict: value.verdict, findings, summary: value.summary };
}

export function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function computeIndependentReviewReportHash(
  report: Omit<IndependentReviewReport, "report_hash"> | IndependentReviewReport,
): string {
  const { report_hash: _ignored, ...body } = report as IndependentReviewReport;
  return sha256CanonicalJson(body);
}

export function finalizeIndependentReviewReport(
  body: Omit<IndependentReviewReport, "report_hash">,
  contracts = new ContractRegistry(),
): IndependentReviewReport {
  const report: IndependentReviewReport = { ...body, report_hash: computeIndependentReviewReportHash(body) };
  contracts.validate<IndependentReviewReport>("independent-review-report", report);
  return report;
}

export function verifyIndependentReviewReport(
  report: IndependentReviewReport,
  contracts = new ContractRegistry(),
): IndependentReviewReport {
  contracts.validate<IndependentReviewReport>("independent-review-report", report);
  if (report.report_hash !== computeIndependentReviewReportHash(report)) {
    throw new ControllerError("REVIEW_REPORT_HASH_MISMATCH", "Independent review report hash mismatch");
  }
  return report;
}

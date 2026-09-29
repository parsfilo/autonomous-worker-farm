import { readFileSync } from "node:fs";
import type { ModelClass } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";
import type { OpenCodeFreeRoutingPolicy } from "./opencode-free-routing.js";

const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const MODEL_PATTERN = /^opencode\/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

export type RuntimeModelStatus =
  | "HEALTHY"
  | "UNAVAILABLE"
  | "RATE_LIMITED"
  | "AUTH_REQUIRED"
  | "INVALID"
  | "TIMEOUT"
  | "BLOCKED";

export interface OpenCodeFreeRuntimeState {
  schema_version: "1.0";
  refreshed_at: string;
  auth_mode: "none";
  machine_id: string;
  worker_image_digest: string;
  gateway_image_digest: string;
  conformance: {
    checked_at: string;
    direct_egress_blocked: true;
    non_opencode_connect_blocked: true;
    keyless_free_model_e2e: true;
  };
  models: Array<{
    model: string;
    status: RuntimeModelStatus;
    duration_ms: number | null;
    probed_at: string;
  }>;
}

export interface RuntimeStateValidationOptions {
  now?: Date;
  maxConformanceAgeMs?: number;
}

const DEFAULT_CONFORMANCE_MAX_AGE_MS = 24 * 60 * 60_000;

function invalid(message: string, details?: Record<string, unknown>): never {
  throw new ControllerError("FREE_MODEL_RUNTIME_STATE_INVALID", message, details);
}

function parseTimestamp(value: unknown, label: string): number {
  if (typeof value !== "string") invalid(label + " must be an ISO timestamp");
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) invalid(label + " must be an ISO timestamp");
  return parsed;
}

function assertFresh(timestamp: number, nowMs: number, maxAgeMs: number, label: string): void {
  if (timestamp > nowMs + 60_000) invalid(label + " is unexpectedly in the future");
  if (nowMs - timestamp > maxAgeMs) invalid(label + " is stale");
}

function isFreeModel(model: string): boolean {
  if (!MODEL_PATTERN.test(model)) return false;
  const id = model.slice("opencode/".length);
  return id === "big-pickle" || id.endsWith("-free");
}

export function validateOpenCodeFreeRuntimeState(
  input: unknown,
  policy: OpenCodeFreeRoutingPolicy,
  options: RuntimeStateValidationOptions = {},
): OpenCodeFreeRuntimeState {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    invalid("runtime state must be an object");
  }
  const value = input as Record<string, unknown>;
  if (value.schema_version !== "1.0") invalid("unsupported runtime state schema_version");
  if (value.auth_mode !== "none") invalid("OpenCode free runtime must remain credentialless");
  if (
    typeof value.machine_id !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.machine_id)
  ) {
    invalid("runtime state machine_id is invalid");
  }

  const now = options.now ?? new Date();
  const nowMs = now.getTime();
  const refreshedAt = parseTimestamp(value.refreshed_at, "refreshed_at");
  assertFresh(
    refreshedAt,
    nowMs,
    policy.document.healthy_max_age_ms,
    "free-model health snapshot",
  );

  if (
    typeof value.worker_image_digest !== "string" ||
    !IMAGE_DIGEST.test(value.worker_image_digest) ||
    value.worker_image_digest !== policy.document.benchmark_basis.worker_image
  ) {
    invalid("worker image digest does not match benchmark-qualified policy");
  }
  if (
    typeof value.gateway_image_digest !== "string" ||
    !IMAGE_DIGEST.test(value.gateway_image_digest) ||
    value.gateway_image_digest !== policy.document.benchmark_basis.gateway_image
  ) {
    invalid("gateway image digest does not match benchmark-qualified policy");
  }

  if (!value.conformance || typeof value.conformance !== "object" || Array.isArray(value.conformance)) {
    invalid("conformance receipt is required");
  }
  const conformance = value.conformance as Record<string, unknown>;
  const conformanceAt = parseTimestamp(conformance.checked_at, "conformance.checked_at");
  assertFresh(
    conformanceAt,
    nowMs,
    options.maxConformanceAgeMs ?? DEFAULT_CONFORMANCE_MAX_AGE_MS,
    "OpenCode free egress conformance",
  );
  if (
    conformance.direct_egress_blocked !== true ||
    conformance.non_opencode_connect_blocked !== true ||
    conformance.keyless_free_model_e2e !== true
  ) {
    invalid("conformance receipt does not prove the required egress invariants");
  }

  if (!Array.isArray(value.models)) invalid("models must be an array");
  const models: OpenCodeFreeRuntimeState["models"] = [];
  const seen = new Set<string>();
  const allowedStatuses = new Set<RuntimeModelStatus>([
    "HEALTHY",
    "UNAVAILABLE",
    "RATE_LIMITED",
    "AUTH_REQUIRED",
    "INVALID",
    "TIMEOUT",
    "BLOCKED",
  ]);
  for (const raw of value.models) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      invalid("model health entry must be an object");
    }
    const record = raw as Record<string, unknown>;
    if (typeof record.model !== "string" || !isFreeModel(record.model)) {
      invalid("runtime state contains a malformed or non-free model", { model: record.model });
    }
    if (seen.has(record.model)) invalid("runtime state contains duplicate model", { model: record.model });
    seen.add(record.model);

    if (typeof record.status !== "string" || !allowedStatuses.has(record.status as RuntimeModelStatus)) {
      invalid("runtime state contains an invalid model status", {
        model: record.model,
        status: record.status,
      });
    }
    const probedAt = parseTimestamp(record.probed_at, "model.probed_at");
    assertFresh(
      probedAt,
      nowMs,
      policy.document.healthy_max_age_ms,
      "model probe " + record.model,
    );
    if (
      record.duration_ms !== null &&
      (!Number.isFinite(record.duration_ms) || Number(record.duration_ms) < 0)
    ) {
      invalid("model duration_ms must be a non-negative number or null", { model: record.model });
    }

    models.push({
      model: record.model,
      status: record.status as RuntimeModelStatus,
      duration_ms: record.duration_ms === null ? null : Number(record.duration_ms),
      probed_at: record.probed_at as string,
    });
  }

  return {
    schema_version: "1.0",
    refreshed_at: value.refreshed_at as string,
    auth_mode: "none",
    machine_id: value.machine_id as string,
    worker_image_digest: value.worker_image_digest as string,
    gateway_image_digest: value.gateway_image_digest as string,
    conformance: {
      checked_at: conformance.checked_at as string,
      direct_egress_blocked: true,
      non_opencode_connect_blocked: true,
      keyless_free_model_e2e: true,
    },
    models,
  };
}

export function loadOpenCodeFreeRuntimeState(
  path: string,
  policy: OpenCodeFreeRoutingPolicy,
  options: RuntimeStateValidationOptions = {},
): OpenCodeFreeRuntimeState {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new ControllerError(
      "FREE_MODEL_RUNTIME_STATE_LOAD_FAILED",
      "Could not read OpenCode free runtime state",
      { path, error: error instanceof Error ? error.message : String(error) },
    );
  }
  return validateOpenCodeFreeRuntimeState(parsed, policy, options);
}

export function healthyModelsFromRuntimeState(state: OpenCodeFreeRuntimeState): Set<string> {
  return new Set(
    state.models.filter((entry) => entry.status === "HEALTHY").map((entry) => entry.model),
  );
}

export function schedulableClassesFromRuntimeState(
  state: OpenCodeFreeRuntimeState,
  policy: OpenCodeFreeRoutingPolicy,
): ModelClass[] {
  const healthy = healthyModelsFromRuntimeState(state);
  const order: ModelClass[] = ["fast", "coding", "deep-reasoning", "review", "frontier"];
  return order.filter((modelClass) =>
    policy.document.classes[modelClass].some((model) => healthy.has(model)),
  );
}

export function selectModelFromRuntimeState(
  state: OpenCodeFreeRuntimeState,
  policy: OpenCodeFreeRoutingPolicy,
  modelClass: ModelClass,
  excludeModels: string[] = [],
): string | null {
  const healthy = healthyModelsFromRuntimeState(state);
  const excluded = new Set(excludeModels);
  return (
    policy.document.classes[modelClass].find(
      (model) => healthy.has(model) && !excluded.has(model),
    ) ?? null
  );
}

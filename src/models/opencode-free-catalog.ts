import type { ModelClass } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";

export const OPENCODE_ZEN_MODELS_URL = "https://opencode.ai/zen/v1/models";
export const OPENCODE_PROVIDER_ID = "opencode";

const EXPLICIT_FREE_IDS = new Set(["big-pickle"]);

export type FreeModelHealthStatus =
  | "UNKNOWN"
  | "HEALTHY"
  | "RATE_LIMITED"
  | "UNAVAILABLE"
  | "AUTH_REQUIRED"
  | "INVALID";

export interface DiscoveredFreeModel {
  id: string;
  model: string;
  discoveredAt: string;
}

export interface FreeModelProbeResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut?: boolean;
  durationMs?: number | null;
}

export interface FreeModelHealthRecord extends DiscoveredFreeModel {
  status: FreeModelHealthStatus;
  lastProbeAt: string | null;
  lastSuccessAt: string | null;
  consecutiveFailures: number;
  successCount: number;
  failureCount: number;
  rateLimitCount: number;
  activeRequests: number;
  cooldownUntil: string | null;
  lastDurationMs: number | null;
}

export interface FreeModelRoutingPolicy {
  classes: Partial<Record<ModelClass, string[]>>;
  perModelMaxConcurrency: number;
  healthyMaxAgeMs: number;
  rateLimitCooldownMs: number;
  failureCooldownMs: number;
}

export interface FreeModelSelection {
  model: string;
  modelId: string;
  status: "HEALTHY";
  activeRequests: number;
  lastDurationMs: number | null;
}

const DEFAULT_POLICY: FreeModelRoutingPolicy = {
  classes: {},
  perModelMaxConcurrency: 1,
  healthyMaxAgeMs: 10 * 60_000,
  rateLimitCooldownMs: 2 * 60_000,
  failureCooldownMs: 30_000,
};

function iso(value: Date): string {
  return value.toISOString();
}

function parseTime(value: string | null): number | null {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function isFreeModelId(id: string): boolean {
  return id.endsWith("-free") || EXPLICIT_FREE_IDS.has(id);
}

function isSafeModelId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(value);
}

export function discoverFreeModels(
  input: unknown,
  now = new Date(),
): DiscoveredFreeModel[] {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new ControllerError("FREE_MODEL_CATALOG_INVALID", "Zen model catalog must be an object");
  }
  const root = input as Record<string, unknown>;
  if (root.object !== "list" || !Array.isArray(root.data)) {
    throw new ControllerError(
      "FREE_MODEL_CATALOG_INVALID",
      "Zen model catalog must be an OpenAI-style list",
    );
  }

  const seen = new Set<string>();
  const discovered: DiscoveredFreeModel[] = [];
  for (const entry of root.data) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const value = entry as Record<string, unknown>;
    if (value.object !== "model" || value.owned_by !== OPENCODE_PROVIDER_ID) continue;
    if (typeof value.id !== "string" || !isSafeModelId(value.id) || !isFreeModelId(value.id)) {
      continue;
    }
    if (seen.has(value.id)) continue;
    seen.add(value.id);
    discovered.push({
      id: value.id,
      model: OPENCODE_PROVIDER_ID + "/" + value.id,
      discoveredAt: iso(now),
    });
  }
  return discovered.sort((a, b) => a.id.localeCompare(b.id));
}

export function classifyFreeModelProbe(result: FreeModelProbeResult): FreeModelHealthStatus {
  const combined = (result.stdout + "\n" + result.stderr).toLowerCase();
  if (result.exitCode === 0 && result.stdout.trim().length > 0 && !result.timedOut) {
    return "HEALTHY";
  }
  if (
    combined.includes("429") ||
    combined.includes("rate limit") ||
    combined.includes("rate-limit") ||
    combined.includes("too many requests") ||
    combined.includes("quota exceeded")
  ) {
    return "RATE_LIMITED";
  }
  if (
    combined.includes("401") ||
    combined.includes("unauthorized") ||
    combined.includes("authentication required") ||
    combined.includes("api key") ||
    combined.includes("no api key") ||
    combined.includes("missing credential")
  ) {
    return "AUTH_REQUIRED";
  }
  if (
    combined.includes("unknown model") ||
    combined.includes("model not found") ||
    combined.includes("invalid model") ||
    combined.includes("404")
  ) {
    return "INVALID";
  }
  return "UNAVAILABLE";
}

export class FreeModelCatalog {
  private readonly records = new Map<string, FreeModelHealthRecord>();
  private readonly policy: FreeModelRoutingPolicy;

  constructor(policy: Partial<FreeModelRoutingPolicy> = {}) {
    const merged: FreeModelRoutingPolicy = {
      ...DEFAULT_POLICY,
      ...policy,
      classes: policy.classes ?? DEFAULT_POLICY.classes,
    };
    if (!Number.isInteger(merged.perModelMaxConcurrency) || merged.perModelMaxConcurrency < 1) {
      throw new ControllerError(
        "FREE_MODEL_POLICY_INVALID",
        "perModelMaxConcurrency must be a positive integer",
      );
    }
    if (
      merged.healthyMaxAgeMs <= 0 ||
      merged.rateLimitCooldownMs <= 0 ||
      merged.failureCooldownMs <= 0
    ) {
      throw new ControllerError(
        "FREE_MODEL_POLICY_INVALID",
        "model health/cooldown durations must be positive",
      );
    }
    this.policy = merged;
  }

  updateDiscovery(models: DiscoveredFreeModel[]): void {
    for (const model of models) {
      const existing = this.records.get(model.model);
      if (existing) {
        existing.discoveredAt = model.discoveredAt;
        continue;
      }
      this.records.set(model.model, {
        ...model,
        status: "UNKNOWN",
        lastProbeAt: null,
        lastSuccessAt: null,
        consecutiveFailures: 0,
        successCount: 0,
        failureCount: 0,
        rateLimitCount: 0,
        activeRequests: 0,
        cooldownUntil: null,
        lastDurationMs: null,
      });
    }

    const currentlyDiscovered = new Set(models.map((entry) => entry.model));
    for (const [model, record] of this.records) {
      if (!currentlyDiscovered.has(model) && record.activeRequests === 0) {
        this.records.delete(model);
      }
    }
  }

  recordProbe(model: string, result: FreeModelProbeResult, now = new Date()): FreeModelHealthRecord {
    const record = this.records.get(model);
    if (!record) {
      throw new ControllerError(
        "FREE_MODEL_NOT_DISCOVERED",
        "Cannot record health for an undiscovered free model",
        { model },
      );
    }

    const status = classifyFreeModelProbe(result);
    record.status = status;
    record.lastProbeAt = iso(now);
    record.lastDurationMs =
      typeof result.durationMs === "number" && Number.isFinite(result.durationMs)
        ? Math.max(0, result.durationMs)
        : null;

    if (status === "HEALTHY") {
      record.lastSuccessAt = iso(now);
      record.successCount += 1;
      record.consecutiveFailures = 0;
      record.cooldownUntil = null;
    } else {
      record.failureCount += 1;
      record.consecutiveFailures += 1;
      if (status === "RATE_LIMITED") {
        record.rateLimitCount += 1;
        record.cooldownUntil = iso(new Date(now.getTime() + this.policy.rateLimitCooldownMs));
      } else if (status === "UNAVAILABLE") {
        record.cooldownUntil = iso(new Date(now.getTime() + this.policy.failureCooldownMs));
      } else {
        record.cooldownUntil = null;
      }
    }

    return { ...record };
  }

  snapshot(): FreeModelHealthRecord[] {
    return [...this.records.values()]
      .map((record) => ({ ...record }))
      .sort((a, b) => a.model.localeCompare(b.model));
  }

  healthyModels(now = new Date()): FreeModelHealthRecord[] {
    const nowMs = now.getTime();
    return this.snapshot().filter((record) => {
      if (record.status !== "HEALTHY" || !record.lastProbeAt) return false;
      const probeAt = parseTime(record.lastProbeAt);
      if (probeAt === null || nowMs - probeAt > this.policy.healthyMaxAgeMs) return false;
      const cooldown = parseTime(record.cooldownUntil);
      if (cooldown !== null && cooldown > nowMs) return false;
      return record.activeRequests < this.policy.perModelMaxConcurrency;
    });
  }

  select(
    modelClass: ModelClass,
    options: {
      excludeModels?: string[];
      now?: Date;
    } = {},
  ): FreeModelSelection | null {
    const allowedByClass = this.policy.classes[modelClass];
    if (!allowedByClass || allowedByClass.length === 0) return null;

    const priority = new Map(allowedByClass.map((model, index) => [model, index]));
    const excluded = new Set(options.excludeModels ?? []);
    const candidates = this.healthyModels(options.now ?? new Date())
      .filter((record) => priority.has(record.model) && !excluded.has(record.model))
      .sort((a, b) => {
        const aPriority = priority.get(a.model) ?? Number.MAX_SAFE_INTEGER;
        const bPriority = priority.get(b.model) ?? Number.MAX_SAFE_INTEGER;
        if (aPriority !== bPriority) return aPriority - bPriority;
        if (a.activeRequests !== b.activeRequests) return a.activeRequests - b.activeRequests;
        if (a.consecutiveFailures !== b.consecutiveFailures) {
          return a.consecutiveFailures - b.consecutiveFailures;
        }
        const aLatency = a.lastDurationMs ?? Number.MAX_SAFE_INTEGER;
        const bLatency = b.lastDurationMs ?? Number.MAX_SAFE_INTEGER;
        if (aLatency !== bLatency) return aLatency - bLatency;
        if (a.successCount !== b.successCount) return b.successCount - a.successCount;
        return a.model.localeCompare(b.model);
      });

    const chosen = candidates[0];
    if (!chosen) return null;
    return {
      model: chosen.model,
      modelId: chosen.id,
      status: "HEALTHY",
      activeRequests: chosen.activeRequests,
      lastDurationMs: chosen.lastDurationMs,
    };
  }

  acquire(model: string): void {
    const record = this.records.get(model);
    if (!record || record.status !== "HEALTHY") {
      throw new ControllerError("FREE_MODEL_NOT_HEALTHY", "Model is not healthy", { model });
    }
    if (record.activeRequests >= this.policy.perModelMaxConcurrency) {
      throw new ControllerError("FREE_MODEL_AT_CAPACITY", "Model has no free inference slot", {
        model,
      });
    }
    record.activeRequests += 1;
  }

  release(model: string): void {
    const record = this.records.get(model);
    if (!record) {
      throw new ControllerError("FREE_MODEL_NOT_DISCOVERED", "Cannot release unknown model", {
        model,
      });
    }
    if (record.activeRequests <= 0) {
      throw new ControllerError(
        "FREE_MODEL_LEASE_UNDERFLOW",
        "Model inference lease count is already zero",
        { model },
      );
    }
    record.activeRequests -= 1;
  }
}

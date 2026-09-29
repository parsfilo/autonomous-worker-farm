import { readFileSync } from "node:fs";
import type { ModelClass, TaskSpec } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";
import {
  FreeModelCatalog,
  type FreeModelRoutingPolicy,
  type FreeModelSelection,
} from "./opencode-free-catalog.js";

const MODEL_CLASSES: ModelClass[] = [
  "fast",
  "coding",
  "deep-reasoning",
  "review",
  "frontier",
];

const SHA256_IMAGE = /^sha256:[0-9a-f]{64}$/;
const MODEL_PATTERN = /^opencode\/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;

export interface OpenCodeFreeRoutingPolicyDocument {
  schema_version: "1.0";
  provider: "opencode";
  route_id: "opencode-free";
  policy_revision: number;
  validated_on: string;
  benchmark_basis: {
    coding_fixture: string;
    review_fixture: string;
    worker_image: string;
    gateway_image: string;
  };
  classes: Record<ModelClass, string[]>;
  per_model_max_concurrency: number;
  healthy_max_age_ms: number;
  rate_limit_cooldown_ms: number;
  failure_cooldown_ms: number;
}

export interface OpenCodeFreeRoutingPolicy {
  document: OpenCodeFreeRoutingPolicyDocument;
  catalogPolicy: FreeModelRoutingPolicy;
}

function invalid(message: string, details?: Record<string, unknown>): never {
  throw new ControllerError("FREE_MODEL_ROUTING_POLICY_INVALID", message, details);
}

function isFreeQualifiedModel(model: string): boolean {
  if (!MODEL_PATTERN.test(model)) return false;
  const id = model.slice("opencode/".length);
  return id === "big-pickle" || id.endsWith("-free");
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isInteger(value) || Number(value) < 1) {
    invalid(label + " must be a positive integer");
  }
  return Number(value);
}

export function validateOpenCodeFreeRoutingPolicy(
  input: unknown,
): OpenCodeFreeRoutingPolicy {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    invalid("routing policy must be an object");
  }
  const value = input as Record<string, unknown>;
  if (value.schema_version !== "1.0") invalid("unsupported routing policy schema_version");
  if (value.provider !== "opencode") invalid("routing policy provider must be opencode");
  if (value.route_id !== "opencode-free") invalid("routing policy route_id must be opencode-free");

  const policyRevision = positiveInteger(value.policy_revision, "policy_revision");
  if (typeof value.validated_on !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value.validated_on)) {
    invalid("validated_on must be YYYY-MM-DD");
  }

  if (!value.benchmark_basis || typeof value.benchmark_basis !== "object" || Array.isArray(value.benchmark_basis)) {
    invalid("benchmark_basis must be an object");
  }
  const benchmark = value.benchmark_basis as Record<string, unknown>;
  for (const key of ["coding_fixture", "review_fixture"] as const) {
    if (typeof benchmark[key] !== "string" || benchmark[key].length < 1 || benchmark[key].length > 128) {
      invalid("invalid benchmark fixture id", { key });
    }
  }
  for (const key of ["worker_image", "gateway_image"] as const) {
    if (typeof benchmark[key] !== "string" || !SHA256_IMAGE.test(benchmark[key])) {
      invalid("invalid benchmark image digest", { key });
    }
  }

  if (!value.classes || typeof value.classes !== "object" || Array.isArray(value.classes)) {
    invalid("classes must be an object");
  }
  const rawClasses = value.classes as Record<string, unknown>;
  const extraClasses = Object.keys(rawClasses).filter(
    (entry) => !MODEL_CLASSES.includes(entry as ModelClass),
  );
  if (extraClasses.length > 0) invalid("unknown model class in routing policy", { extraClasses });

  const classes = {} as Record<ModelClass, string[]>;
  for (const modelClass of MODEL_CLASSES) {
    const raw = rawClasses[modelClass];
    if (!Array.isArray(raw)) invalid("every model class must have an array", { modelClass });
    const models: string[] = [];
    const seen = new Set<string>();
    for (const entry of raw) {
      if (typeof entry !== "string" || !isFreeQualifiedModel(entry)) {
        invalid("class contains a non-free or malformed OpenCode model", {
          modelClass,
          model: entry,
        });
      }
      if (seen.has(entry)) invalid("class contains duplicate model", { modelClass, model: entry });
      seen.add(entry);
      models.push(entry);
    }
    classes[modelClass] = models;
  }

  if (classes.frontier.length !== 0) {
    invalid("frontier class is reserved for the Multica master and must be empty");
  }

  const perModelMaxConcurrency = positiveInteger(
    value.per_model_max_concurrency,
    "per_model_max_concurrency",
  );
  const healthyMaxAgeMs = positiveInteger(value.healthy_max_age_ms, "healthy_max_age_ms");
  const rateLimitCooldownMs = positiveInteger(
    value.rate_limit_cooldown_ms,
    "rate_limit_cooldown_ms",
  );
  const failureCooldownMs = positiveInteger(
    value.failure_cooldown_ms,
    "failure_cooldown_ms",
  );

  const document: OpenCodeFreeRoutingPolicyDocument = {
    schema_version: "1.0",
    provider: "opencode",
    route_id: "opencode-free",
    policy_revision: policyRevision,
    validated_on: value.validated_on as string,
    benchmark_basis: {
      coding_fixture: benchmark.coding_fixture as string,
      review_fixture: benchmark.review_fixture as string,
      worker_image: benchmark.worker_image as string,
      gateway_image: benchmark.gateway_image as string,
    },
    classes,
    per_model_max_concurrency: perModelMaxConcurrency,
    healthy_max_age_ms: healthyMaxAgeMs,
    rate_limit_cooldown_ms: rateLimitCooldownMs,
    failure_cooldown_ms: failureCooldownMs,
  };

  return {
    document,
    catalogPolicy: {
      classes,
      perModelMaxConcurrency,
      healthyMaxAgeMs,
      rateLimitCooldownMs,
      failureCooldownMs,
    },
  };
}

export function loadOpenCodeFreeRoutingPolicy(path: string): OpenCodeFreeRoutingPolicy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new ControllerError(
      "FREE_MODEL_ROUTING_POLICY_LOAD_FAILED",
      "Could not read OpenCode free routing policy",
      { path, error: error instanceof Error ? error.message : String(error) },
    );
  }
  return validateOpenCodeFreeRoutingPolicy(parsed);
}

export function schedulableFreeModelClasses(
  catalog: FreeModelCatalog,
  now = new Date(),
): ModelClass[] {
  return MODEL_CLASSES.filter((modelClass) => catalog.select(modelClass, { now }) !== null);
}

export function selectOpenCodeFreeModelForTask(
  task: TaskSpec,
  catalog: FreeModelCatalog,
  options: {
    now?: Date;
    diversitySourceModel?: string | null;
    excludeModels?: string[];
  } = {},
): FreeModelSelection | null {
  const privacy = task.model_requirements.privacy_class ?? "public";
  if (privacy !== "public") {
    return null;
  }

  const diversityAttemptId = task.model_requirements.provider_diversity_from_attempt_id;
  if (diversityAttemptId && !options.diversitySourceModel) {
    throw new ControllerError(
      "DIVERSITY_SOURCE_MODEL_REQUIRED",
      "Task requires provider/model diversity but the source attempt model was not supplied",
      { attemptId: diversityAttemptId },
    );
  }

  const excluded = new Set(options.excludeModels ?? []);
  if (options.diversitySourceModel) excluded.add(options.diversitySourceModel);

  return catalog.select(task.model_requirements.class, {
    ...(options.now ? { now: options.now } : {}),
    excludeModels: [...excluded],
  });
}

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import * as formatsModule from "ajv-formats";
import { ControllerError } from "../lib/errors.js";
import { findProjectRoot } from "../lib/project-root.js";

export type ContractName =
  | "task-spec"
  | "result-manifest"
  | "repo-passport"
  | "worker-profile"
  | "machine-capability"
  | "harness-capability"
  | "task-state-event"
  | "controller-intent"
  | "sandbox-request"
  | "sandbox-attestation"
  | "candidate-descriptor"
  | "validation-plan"
  | "quality-profile"
  | "verification-report"
  | "sandbox-workspace-lease"
  | "egress-profile"
  | "independent-review-report"
  | "git-integration-artifact"
  | "remote-verification-report"
  | "github-pr-publication"
  | "github-merge-receipt"
  | "post-merge-verification-report"
  | "github-actions-execution-receipt";

function renderErrors(errors: ErrorObject[] | null | undefined): string {
  if (!errors?.length) return "unknown schema validation error";
  return errors
    .map((error) => {
      const location = error.instancePath || "<root>";
      return `${location}: ${error.message ?? "invalid"}`;
    })
    .join("; ");
}

export class ContractRegistry {
  readonly #root: string;
  readonly #validators = new Map<ContractName, ValidateFunction>();

  constructor(root = findProjectRoot()) {
    this.#root = root;
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    const addFormats = (formatsModule as unknown as { default: (instance: Ajv2020) => unknown }).default;
    addFormats(ajv);

    const names: ContractName[] = [
      "task-spec",
      "result-manifest",
      "repo-passport",
      "worker-profile",
      "machine-capability",
      "harness-capability",
      "task-state-event",
      "controller-intent",
      "sandbox-request",
      "sandbox-attestation",
      "candidate-descriptor",
      "validation-plan",
      "quality-profile",
      "verification-report",
      "sandbox-workspace-lease",
      "egress-profile",
      "independent-review-report",
      "git-integration-artifact",
      "remote-verification-report",
      "github-pr-publication",
      "github-merge-receipt",
      "post-merge-verification-report",
      "github-actions-execution-receipt",
    ];

    for (const name of names) {
      const path = join(this.#root, "contracts", `${name}.schema.json`);
      const schema = JSON.parse(readFileSync(path, "utf8")) as object;
      this.#validators.set(name, ajv.compile(schema));
    }
  }

  validate<T>(name: ContractName, value: unknown): T {
    const validator = this.#validators.get(name);
    if (!validator) throw new ControllerError("SCHEMA_NOT_FOUND", `No validator registered for ${name}`);

    if (!validator(value)) {
      throw new ControllerError("CONTRACT_INVALID", `${name} failed validation: ${renderErrors(validator.errors)}`, {
        contract: name,
        errors: validator.errors ?? [],
      });
    }

    return value as T;
  }
}

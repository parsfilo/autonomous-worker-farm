import { ControllerError } from "../lib/errors.js";

export type ExecutionBackend = "local-broker" | "github-actions";

export interface GitHubActionsBackendConfig {
  backend: "github-actions";
  machineId: string;
  maxSlots: number;
  workerRepo: string;
  workflow: string;
  dispatchRef: string;
  workflowSha: string;
}

export interface LocalBrokerBackendConfig {
  backend: "local-broker";
}

export type ExecutionBackendConfig =
  | LocalBrokerBackendConfig
  | GitHubActionsBackendConfig;

function required(
  env: NodeJS.ProcessEnv,
  name: string,
): string {
  const value = env[name]?.trim();
  if (!value) {
    throw new ControllerError(
      "GITHUB_ACTIONS_BACKEND_UNCONFIGURED",
      name + " is required when AWF_EXECUTION_BACKEND=github-actions",
    );
  }
  return value;
}

export function loadExecutionBackendConfig(
  env: NodeJS.ProcessEnv = process.env,
): ExecutionBackendConfig {
  const raw = (env.AWF_EXECUTION_BACKEND ?? "local-broker").trim();
  if (raw === "local-broker") return { backend: "local-broker" };
  if (raw !== "github-actions") {
    throw new ControllerError(
      "EXECUTION_BACKEND_INVALID",
      "AWF_EXECUTION_BACKEND must be local-broker or github-actions",
      { value: raw },
    );
  }

  const workerRepo = required(env, "AWF_GITHUB_ACTIONS_WORKER_REPO");
  if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(workerRepo)) {
    throw new ControllerError(
      "GITHUB_ACTIONS_BACKEND_UNCONFIGURED",
      "AWF_GITHUB_ACTIONS_WORKER_REPO must be owner/repo",
    );
  }
  const workflow = required(env, "AWF_GITHUB_ACTIONS_WORKFLOW");
  if (!/^[A-Za-z0-9._-]+\.ya?ml$/.test(workflow)) {
    throw new ControllerError(
      "GITHUB_ACTIONS_BACKEND_UNCONFIGURED",
      "AWF_GITHUB_ACTIONS_WORKFLOW must be a workflow YAML filename",
    );
  }
  const dispatchRef = required(env, "AWF_GITHUB_ACTIONS_REF");
  if (
    !/^[A-Za-z0-9._\/-]{1,255}$/.test(dispatchRef) ||
    dispatchRef.startsWith("/") ||
    dispatchRef.endsWith("/") ||
    dispatchRef.includes("..") ||
    dispatchRef.includes("//")
  ) {
    throw new ControllerError(
      "GITHUB_ACTIONS_BACKEND_UNCONFIGURED",
      "AWF_GITHUB_ACTIONS_REF must be a safe branch name",
    );
  }
  const workflowSha = required(env, "AWF_GITHUB_ACTIONS_WORKFLOW_SHA").toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(workflowSha)) {
    throw new ControllerError(
      "GITHUB_ACTIONS_BACKEND_UNCONFIGURED",
      "AWF_GITHUB_ACTIONS_WORKFLOW_SHA must be an exact 40-character Git commit SHA",
    );
  }
  const machineId =
    env.AWF_GITHUB_ACTIONS_MACHINE_ID?.trim() || "github-actions-standard";
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(machineId)) {
    throw new ControllerError(
      "GITHUB_ACTIONS_BACKEND_UNCONFIGURED",
      "AWF_GITHUB_ACTIONS_MACHINE_ID is invalid",
    );
  }
  const maxSlots = Number.parseInt(
    env.AWF_GITHUB_ACTIONS_MAX_SLOTS?.trim() || "20",
    10,
  );
  if (!Number.isInteger(maxSlots) || maxSlots < 1 || maxSlots > 20) {
    throw new ControllerError(
      "GITHUB_ACTIONS_BACKEND_UNCONFIGURED",
      "AWF_GITHUB_ACTIONS_MAX_SLOTS must be 1..20",
    );
  }

  return {
    backend: "github-actions",
    machineId,
    maxSlots,
    workerRepo,
    workflow,
    dispatchRef,
    workflowSha,
  };
}

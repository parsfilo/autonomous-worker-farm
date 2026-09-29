import { request as httpRequest } from "node:http";
import type {
  SandboxAttestation,
  SandboxRequest,
  SandboxWorkspaceLease,
} from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { ControllerError } from "../lib/errors.js";
import { verifySandboxAttestation } from "./verify-attestation.js";

export interface SandboxBrokerHealth {
  status: "ready" | "not_ready";
  broker_build: string;
  machine_id: string;
  controller_uid: number;
  runtime_ready: boolean;
  workspace_manager_ready: boolean;
}

export interface WorkspaceLeaseRequest {
  attempt_id: string;
  machine_id: string;
  ttl_seconds: number;
}

export interface WorkspaceLeaseReleaseResult {
  status: "RELEASED";
  attempt_id: string;
  machine_id: string;
  lease_id: string;
  removed: boolean;
}

export interface TerminateResult {
  status: "TERMINATED";
  request_id: string;
  attempt_id: string;
  removed: boolean;
}

export interface AttemptStatusResult {
  schema_version: "1.0";
  request_id: string;
  attempt_id: string;
  state: "RUNNING" | "EXITED" | "NOT_FOUND";
  running: boolean;
  exit_code: number | null;
  container_id: string | null;
  stdout_tail: string;
  stderr_tail: string;
  logs_available: boolean;
  observed_at: string;
}

export interface SandboxBrokerClientOptions {
  socketPath?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export class SandboxBrokerClient {
  readonly #socketPath: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #contracts: ContractRegistry;

  constructor(options: SandboxBrokerClientOptions = {}, contracts = new ContractRegistry()) {
    this.#socketPath = options.socketPath ?? "/run/autonomous-worker/sandbox-broker.sock";
    this.#timeoutMs = options.timeoutMs ?? 10_000;
    this.#maxResponseBytes = options.maxResponseBytes ?? 2 * 1024 * 1024;
    this.#contracts = contracts;
  }

  async health(): Promise<SandboxBrokerHealth> {
    const value = await this.#requestJson("GET", "/v1/health");
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Broker health response must be an object");
    }
    const record = value as Record<string, unknown>;
    if (
      (record.status !== "ready" && record.status !== "not_ready") ||
      typeof record.broker_build !== "string" ||
      typeof record.machine_id !== "string" ||
      record.machine_id.length === 0 ||
      typeof record.controller_uid !== "number" ||
      typeof record.runtime_ready !== "boolean" ||
      typeof record.workspace_manager_ready !== "boolean"
    ) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Broker health response has invalid fields");
    }
    return record as unknown as SandboxBrokerHealth;
  }

  async issueWorkspaceLease(input: WorkspaceLeaseRequest): Promise<SandboxWorkspaceLease> {
    if (
      !input.attempt_id ||
      !input.machine_id ||
      !Number.isInteger(input.ttl_seconds) ||
      input.ttl_seconds < 1 ||
      input.ttl_seconds > 3600
    ) {
      throw new ControllerError("BROKER_REQUEST_INVALID", "Invalid workspace lease request");
    }

    const value = await this.#requestJson("POST", "/v1/workspace-leases", input);
    return this.#contracts.validate<SandboxWorkspaceLease>("sandbox-workspace-lease", value);
  }

  async releaseWorkspaceLease(lease: SandboxWorkspaceLease): Promise<WorkspaceLeaseReleaseResult> {
    const value = await this.#requestJson("POST", "/v1/workspace-leases/release", {
      attempt_id: lease.attempt_id,
      machine_id: lease.machine_id,
      lease_id: lease.lease_id,
      lease_hash: lease.lease_hash,
    });
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Workspace lease release response must be an object");
    }
    const record = value as Record<string, unknown>;
    if (
      record.status !== "RELEASED" ||
      record.attempt_id !== lease.attempt_id ||
      record.machine_id !== lease.machine_id ||
      record.lease_id !== lease.lease_id ||
      typeof record.removed !== "boolean"
    ) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Workspace lease release response has invalid fields");
    }
    return record as unknown as WorkspaceLeaseReleaseResult;
  }

  async provision(input: SandboxRequest): Promise<SandboxAttestation> {
    const request = this.#contracts.validate<SandboxRequest>("sandbox-request", input);
    const value = await this.#requestJson("POST", "/v1/provision", request);
    const attestation = this.#contracts.validate<SandboxAttestation>("sandbox-attestation", value);
    verifySandboxAttestation(request, attestation, this.#contracts);
    return attestation;
  }

  async status(requestId: string, attemptId: string): Promise<AttemptStatusResult> {
    if (!requestId || !attemptId) {
      throw new ControllerError("BROKER_REQUEST_INVALID", "requestId and attemptId are required");
    }
    const value = await this.#requestJson("POST", "/v1/status", {
      request_id: requestId,
      attempt_id: attemptId,
    });
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Attempt status response must be an object");
    }
    const record = value as Record<string, unknown>;
    const state = record.state;
    const exitCode = record.exit_code;
    const containerId = record.container_id;
    if (
      record.schema_version !== "1.0" ||
      record.request_id !== requestId ||
      record.attempt_id !== attemptId ||
      (state !== "RUNNING" && state !== "EXITED" && state !== "NOT_FOUND") ||
      typeof record.running !== "boolean" ||
      (exitCode !== null && (!Number.isInteger(exitCode) || Number(exitCode) < 0)) ||
      (containerId !== null &&
        (typeof containerId !== "string" || !/^[0-9a-f]{12,64}$/.test(containerId))) ||
      typeof record.stdout_tail !== "string" ||
      typeof record.stderr_tail !== "string" ||
      typeof record.logs_available !== "boolean" ||
      typeof record.observed_at !== "string" ||
      !Number.isFinite(Date.parse(record.observed_at))
    ) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Attempt status response has invalid fields");
    }
    if (
      (state === "RUNNING" && (record.running !== true || exitCode !== null || containerId === null)) ||
      (state === "EXITED" && (record.running !== false || exitCode === null || containerId === null)) ||
      (state === "NOT_FOUND" && (record.running !== false || exitCode !== null || containerId !== null))
    ) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Attempt status state invariants are inconsistent");
    }
    return record as unknown as AttemptStatusResult;
  }

  async terminate(requestId: string, attemptId: string): Promise<TerminateResult> {
    if (!requestId || !attemptId) {
      throw new ControllerError("BROKER_REQUEST_INVALID", "requestId and attemptId are required");
    }
    const value = await this.#requestJson("POST", "/v1/terminate", {
      request_id: requestId,
      attempt_id: attemptId,
    });
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Terminate response must be an object");
    }
    const record = value as Record<string, unknown>;
    if (
      record.status !== "TERMINATED" ||
      record.request_id !== requestId ||
      record.attempt_id !== attemptId ||
      typeof record.removed !== "boolean"
    ) {
      throw new ControllerError("BROKER_RESPONSE_INVALID", "Terminate response has invalid fields");
    }
    return record as unknown as TerminateResult;
  }

  async #requestJson(method: "GET" | "POST", path: string, body?: unknown): Promise<unknown> {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");

    return await new Promise<unknown>((resolve, reject) => {
      const req = httpRequest(
        {
          socketPath: this.#socketPath,
          path,
          method,
          // Broker RPCs are short-lived and must not keep Unix sockets in the
          // Controller event loop after a request completes.
          agent: false,
          headers:
            payload === undefined
              ? { Accept: "application/json" }
              : {
                  Accept: "application/json",
                  "Content-Type": "application/json",
                  "Content-Length": String(payload.byteLength),
                },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;

          res.on("data", (chunk: Buffer | string) => {
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            size += buffer.byteLength;
            if (size > this.#maxResponseBytes) {
              req.destroy(
                new ControllerError(
                  "BROKER_RESPONSE_TOO_LARGE",
                  "Broker response exceeded configured maximum size",
                ),
              );
              return;
            }
            chunks.push(buffer);
          });

          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            let decoded: unknown;
            try {
              decoded = text.length ? JSON.parse(text) : null;
            } catch (error) {
              reject(
                new ControllerError("BROKER_RESPONSE_INVALID_JSON", "Broker returned invalid JSON", {
                  cause: error instanceof Error ? error.message : String(error),
                }),
              );
              return;
            }

            const status = res.statusCode ?? 0;
            if (status < 200 || status >= 300) {
              const errorRecord =
                decoded && typeof decoded === "object" && !Array.isArray(decoded)
                  ? (decoded as Record<string, unknown>).error
                  : null;
              const brokerError =
                errorRecord && typeof errorRecord === "object" && !Array.isArray(errorRecord)
                  ? (errorRecord as Record<string, unknown>)
                  : null;
              reject(
                new ControllerError(
                  typeof brokerError?.code === "string" ? brokerError.code : "BROKER_HTTP_ERROR",
                  typeof brokerError?.message === "string"
                    ? brokerError.message
                    : "Sandbox broker request failed with HTTP " + status,
                  { status, path },
                ),
              );
              return;
            }

            resolve(decoded);
          });
        },
      );

      req.setTimeout(this.#timeoutMs, () => {
        req.destroy(new ControllerError("BROKER_TIMEOUT", "Sandbox broker request timed out"));
      });
      req.on("error", (error) => reject(error));

      if (payload) req.write(payload);
      req.end();
    });
  }
}

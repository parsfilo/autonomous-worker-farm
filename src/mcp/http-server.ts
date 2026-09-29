import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { ControllerCore } from "../controller/controller.js";
import { loadExecutionBackendConfig } from "../execution/backend-config.js";
import { githubActionsMachineCapability } from "../machine/github-actions.js";
import { findProjectRoot } from "../lib/project-root.js";
import { buildServer } from "./server.js";

const MAX_BODY_BYTES = 1024 * 1024;

function isLoopback(address: string | undefined): boolean {
  if (!address) return false;
  return (
    address === "127.0.0.1" ||
    address === "::1" ||
    address === "::ffff:127.0.0.1"
  );
}

function tokenMatches(header: string | undefined, token: string): boolean {
  if (!header?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice("Bearer ".length), "utf8");
  const expected = Buffer.from(token, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error("REQUEST_TOO_LARGE");
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function copyResponseHeaders(response: Response, res: ServerResponse): void {
  response.headers.forEach((value, key) => {
    res.setHeader(key, value);
  });
}

export interface ControllerMcpHttpOptions {
  statePath: string;
  token: string;
  host?: string;
  port?: number;
  freeModelPolicyPath?: string;
  freeModelStatePath?: string;
}

export function createControllerMcpHttpServer(options: ControllerMcpHttpOptions) {
  if (!options.token || options.token.length < 32) {
    throw new Error("Controller MCP bearer token must be at least 32 characters");
  }
  const host = options.host ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1") {
    throw new Error("Controller MCP HTTP server must bind to loopback");
  }
  const projectRoot = findProjectRoot();
  const backend = loadExecutionBackendConfig();
  const core = new ControllerCore({
    statePath: options.statePath,
    freeModelPolicyPath:
      options.freeModelPolicyPath ??
      join(projectRoot, "policies", "opencode-free-routing.json"),
    freeModelStatePath:
      options.freeModelStatePath ??
      join(projectRoot, ".state", "opencode-free-runtime.json"),
    localVerificationEnabled: true,
    executionBackend: backend.backend,
    ...(backend.backend === "github-actions"
      ? { githubActionsMachineId: backend.machineId }
      : {}),
  });
  if (backend.backend === "github-actions") {
    core.registerMachine(
      githubActionsMachineCapability({
        machineId: backend.machineId,
        maxSlots: backend.maxSlots,
      }),
    );
  }
  const handler = createMcpHandler(() => buildServer(core), {
    legacy: "stateless",
    responseMode: "auto",
    maxRequestBodySize: MAX_BODY_BYTES,
  });

  const server = createServer(async (req, res) => {
    try {
      if (!isLoopback(req.socket.remoteAddress)) {
        res.writeHead(403).end("loopback only\n");
        return;
      }

      const url = new URL(req.url ?? "/", `http://${host}:${options.port ?? 18777}`);
      if (url.pathname === "/healthz") {
        if (req.method !== "GET") {
          res.writeHead(405).end("method not allowed\n");
          return;
        }
        res.setHeader("content-type", "application/json");
        res.writeHead(200).end(
          JSON.stringify({ status: "ready", service: "autonomous-worker-controller-mcp" }) +
            "\n",
        );
        return;
      }

      if (url.pathname !== "/mcp") {
        res.writeHead(404).end("not found\n");
        return;
      }

      if (!tokenMatches(req.headers.authorization, options.token)) {
        res.setHeader("www-authenticate", 'Bearer realm="autonomous-worker-controller"');
        res.writeHead(401).end("unauthorized\n");
        return;
      }

      let body: Buffer | undefined;
      if (req.method !== "GET" && req.method !== "HEAD") {
        body = await readBody(req);
      }

      const requestHeaders = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (Array.isArray(value)) {
          for (const item of value) requestHeaders.append(key, item);
        } else if (value !== undefined) {
          requestHeaders.set(key, value);
        }
      }

      const method = req.method ?? "GET";
      const webRequest = new Request(url, {
        method,
        headers: requestHeaders,
        ...(body && body.length > 0 ? { body } : {}),
      });
      const response = await handler.fetch(webRequest);
      copyResponseHeaders(response, res);
      res.statusCode = response.status;
      const responseBody = Buffer.from(await response.arrayBuffer());
      res.end(responseBody);
    } catch (error) {
      if (error instanceof Error && error.message === "REQUEST_TOO_LARGE") {
        res.writeHead(413).end("request too large\n");
      } else {
        console.error("controller-mcp-http request failed", error);
        if (!res.headersSent) res.writeHead(500);
        res.end("internal error\n");
      }
    }
  });

  server.on("close", () => {
    void handler.close();
  });
  return server;
}

export function loadControllerMcpToken(path: string): string {
  const token = readFileSync(path, "utf8").trim();
  if (token.length < 32) throw new Error("Controller MCP token file is invalid");
  return token;
}

export function defaultControllerStatePath(): string {
  return join(findProjectRoot(), ".state", "controller-state.json");
}

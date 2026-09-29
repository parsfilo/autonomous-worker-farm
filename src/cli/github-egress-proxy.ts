import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as netConnect } from "node:net";
import { URL } from "node:url";

const MAX_REQUEST_BYTES = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const ALLOWED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "x-awf-upstream-url",
  "x-awf-proxy-token",
]);

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error("missing required environment variable: " + name);
  return value;
}

function tokenMatches(provided: string | undefined, expected: string): boolean {
  if (!provided) return false;
  const a = Buffer.from(provided, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function allowedInitialUrl(url: URL): boolean {
  if (url.protocol !== "https:") return false;
  if (url.hostname === "api.github.com") {
    return url.pathname.startsWith("/repos/") || url.pathname.startsWith("/app/installations/");
  }
  if (url.hostname === "token.actions.githubusercontent.com") {
    return url.pathname === "/.well-known/openid-configuration" || url.pathname === "/.well-known/jwks";
  }
  return false;
}

function allowedArtifactRedirect(url: URL): boolean {
  if (url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  return (
    host.endsWith(".blob.core.windows.net") ||
    host.endsWith(".actions.githubusercontent.com") ||
    host.endsWith(".githubusercontent.com") ||
    host === "objects.githubusercontent.com"
  );
}

function isArtifactZipPath(url: URL): boolean {
  return /^\/repos\/[^/]+\/[^/]+\/actions\/artifacts\/\d+\/zip$/.test(url.pathname);
}

function cleanRequestHeaders(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (HOP_BY_HOP.has(key.toLowerCase()) || value === undefined) continue;
    result[key] = Array.isArray(value) ? value : String(value);
  }
  return result;
}

function cleanResponseHeaders(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (HOP_BY_HOP.has(key.toLowerCase()) || value === undefined) continue;
    if (key.toLowerCase() === "set-cookie") continue;
    result[key] = Array.isArray(value) ? value : String(value);
  }
  return result;
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const raw of req) {
    const chunk = Buffer.from(raw);
    total += chunk.length;
    if (total > MAX_REQUEST_BYTES) throw new Error("request body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function forward(input: {
  url: URL;
  method: string;
  headers: Record<string, string | string[]>;
  body: Buffer;
  response: ServerResponse;
  redirects: number;
  artifactRedirectAllowed: boolean;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      input.url,
      {
        method: input.method,
        headers: input.headers,
        timeout: 30_000,
      },
      (upstream) => {
        const status = upstream.statusCode ?? 502;
        const location = upstream.headers.location;
        if (
          location &&
          [301, 302, 303, 307, 308].includes(status) &&
          input.redirects < MAX_REDIRECTS &&
          input.method === "GET" &&
          input.artifactRedirectAllowed
        ) {
          upstream.resume();
          let next: URL;
          try {
            next = new URL(location, input.url);
          } catch {
            reject(new Error("invalid upstream redirect URL"));
            return;
          }
          if (!allowedArtifactRedirect(next)) {
            reject(new Error("artifact redirect host is not allowed"));
            return;
          }
          const redirectedHeaders = { ...input.headers };
          for (const key of Object.keys(redirectedHeaders)) {
            if (key.toLowerCase() === "authorization") delete redirectedHeaders[key];
          }
          forward({
            ...input,
            url: next,
            headers: redirectedHeaders,
            body: Buffer.alloc(0),
            redirects: input.redirects + 1,
          }).then(resolve, reject);
          return;
        }

        input.response.writeHead(status, cleanResponseHeaders(upstream.headers));
        let total = 0;
        upstream.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_RESPONSE_BYTES) {
            upstream.destroy(new Error("upstream response too large"));
            return;
          }
          input.response.write(chunk);
        });
        upstream.on("end", () => {
          input.response.end();
          resolve();
        });
        upstream.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("upstream timeout")));
    req.on("error", reject);
    if (input.body.length > 0) req.write(input.body);
    req.end();
  });
}

async function main(): Promise<void> {
  const host = process.env.AWF_GITHUB_EGRESS_PROXY_HOST?.trim() || "127.0.0.1";
  const port = Number.parseInt(process.env.AWF_GITHUB_EGRESS_PROXY_PORT?.trim() || "18778", 10);
  const tokenPath = requiredEnv("AWF_GITHUB_EGRESS_PROXY_TOKEN_FILE");
  const token = readFileSync(tokenPath, "utf8").trim();
  if (host !== "127.0.0.1" || !Number.isInteger(port) || port < 1024 || port > 65535 || token.length < 32) {
    throw new Error("invalid GitHub egress proxy configuration");
  }

  const server = createServer(async (req, res) => {
    try {
      if (req.url === "/healthz" && req.method === "GET") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: "ready" }));
        return;
      }
      if (req.url !== "/forward") {
        res.writeHead(404).end();
        return;
      }
      const method = (req.method || "GET").toUpperCase();
      if (!ALLOWED_METHODS.has(method)) {
        res.writeHead(405).end();
        return;
      }
      const providedToken = Array.isArray(req.headers["x-awf-proxy-token"])
        ? req.headers["x-awf-proxy-token"][0]
        : req.headers["x-awf-proxy-token"];
      if (!tokenMatches(providedToken, token)) {
        res.writeHead(401).end();
        return;
      }
      const rawUrl = Array.isArray(req.headers["x-awf-upstream-url"])
        ? req.headers["x-awf-upstream-url"][0]
        : req.headers["x-awf-upstream-url"];
      if (!rawUrl) {
        res.writeHead(400).end();
        return;
      }
      let upstreamUrl: URL;
      try {
        upstreamUrl = new URL(rawUrl);
      } catch {
        res.writeHead(400).end();
        return;
      }
      if (!allowedInitialUrl(upstreamUrl)) {
        res.writeHead(403).end();
        return;
      }
      const body = await readBody(req);
      const headers = cleanRequestHeaders(req.headers);
      await forward({
        url: upstreamUrl,
        method,
        headers,
        body,
        response: res,
        redirects: 0,
        artifactRedirectAllowed: isArtifactZipPath(upstreamUrl),
      });
    } catch (error) {
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
      } else {
        res.destroy(error instanceof Error ? error : new Error(String(error)));
      }
    }
  });

  server.on("connect", (req, clientSocket, head) => {
    if (req.url !== "github.com:443") {
      clientSocket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    const upstream = netConnect({ host: "github.com", port: 443 });
    upstream.setTimeout(30_000);
    upstream.once("connect", () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    const closeBoth = () => {
      upstream.destroy();
      clientSocket.destroy();
    };
    upstream.on("timeout", closeBoth);
    upstream.on("error", closeBoth);
    clientSocket.on("error", () => upstream.destroy());
  });

  server.listen(port, host, () => {
    process.stdout.write(`autonomous-worker GitHub egress proxy ready; http://${host}:${port}/forward\n`);
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});

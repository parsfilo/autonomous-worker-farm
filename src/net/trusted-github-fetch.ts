import { readFileSync } from "node:fs";
import { ControllerError } from "../lib/errors.js";

type FetchInput = Parameters<typeof fetch>[0];
type FetchBody = RequestInit["body"];

const DIRECT_ALLOWED_HOSTS = new Set([
  "api.github.com",
  "token.actions.githubusercontent.com",
]);

export interface TrustedGitHubFetchOptions {
  proxyUrl: string;
  proxyToken: string;
  localFetch?: typeof fetch;
}

function validateUpstream(url: URL): void {
  if (url.protocol !== "https:" || !DIRECT_ALLOWED_HOSTS.has(url.hostname)) {
    throw new ControllerError(
      "GITHUB_EGRESS_TARGET_FORBIDDEN",
      "Trusted GitHub fetch only permits approved GitHub API/OIDC hosts",
      { host: url.hostname, protocol: url.protocol },
    );
  }
}

function mergeHeaders(input: FetchInput, init?: RequestInit): Headers {
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  const override = new Headers(init?.headers);
  override.forEach((value, key) => headers.set(key, value));
  headers.delete("host");
  headers.delete("connection");
  headers.delete("transfer-encoding");
  headers.delete("content-length");
  return headers;
}

export function createTrustedGitHubFetch(
  options: TrustedGitHubFetchOptions,
): typeof fetch {
  const localFetch = options.localFetch ?? globalThis.fetch;
  let parsedProxy: URL;
  try {
    parsedProxy = new URL(options.proxyUrl);
  } catch {
    throw new ControllerError(
      "GITHUB_EGRESS_PROXY_CONFIG_INVALID",
      "GitHub egress proxy URL is invalid",
    );
  }
  if (
    parsedProxy.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]", "::1"].includes(parsedProxy.hostname)
  ) {
    throw new ControllerError(
      "GITHUB_EGRESS_PROXY_CONFIG_INVALID",
      "GitHub egress proxy must be loopback HTTP",
      { proxyUrl: options.proxyUrl },
    );
  }
  if (!options.proxyToken || options.proxyToken.length < 32) {
    throw new ControllerError(
      "GITHUB_EGRESS_PROXY_CONFIG_INVALID",
      "GitHub egress proxy token is missing or too short",
    );
  }

  return (async (
    input: FetchInput,
    init?: RequestInit,
  ): Promise<Response> => {
    const upstream = new URL(input instanceof Request ? input.url : String(input));
    validateUpstream(upstream);
    const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const headers = mergeHeaders(input, init);
    headers.set("x-awf-upstream-url", upstream.toString());
    headers.set("x-awf-proxy-token", options.proxyToken);

    let body: FetchBody | null | undefined = init?.body;
    if (body === undefined && input instanceof Request && !["GET", "HEAD"].includes(method)) {
      body = await input.clone().arrayBuffer();
    }

    return localFetch(parsedProxy, {
      method,
      headers,
      ...(body === undefined || body === null ? {} : { body }),
      redirect: "manual",
    });
  }) as typeof fetch;
}


export function trustedGitProxyEnv(): Record<string, string> {
  const raw = process.env.AWF_GITHUB_GIT_PROXY_URL?.trim();
  if (!raw) return {};
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ControllerError(
      "GITHUB_GIT_PROXY_CONFIG_INVALID",
      "AWF_GITHUB_GIT_PROXY_URL is invalid",
    );
  }
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)
  ) {
    throw new ControllerError(
      "GITHUB_GIT_PROXY_CONFIG_INVALID",
      "GitHub Git proxy must be loopback HTTP",
      { proxy: raw },
    );
  }
  return { HTTPS_PROXY: raw, https_proxy: raw };
}

let cached: { key: string; fetchImpl: typeof fetch } | null = null;

export const trustedGitHubFetch: typeof fetch = (async (
  input: FetchInput,
  init?: RequestInit,
): Promise<Response> => {
  const proxyUrl = process.env.AWF_GITHUB_EGRESS_PROXY_URL?.trim();
  const tokenPath = process.env.AWF_GITHUB_EGRESS_PROXY_TOKEN_FILE?.trim();
  if (!proxyUrl && !tokenPath) {
    return globalThis.fetch(input, init);
  }
  if (!proxyUrl || !tokenPath) {
    throw new ControllerError(
      "GITHUB_EGRESS_PROXY_CONFIG_INVALID",
      "Both AWF_GITHUB_EGRESS_PROXY_URL and AWF_GITHUB_EGRESS_PROXY_TOKEN_FILE are required",
    );
  }
  let token: string;
  try {
    token = readFileSync(tokenPath, "utf8").trim();
  } catch (error) {
    throw new ControllerError(
      "GITHUB_EGRESS_PROXY_TOKEN_LOAD_FAILED",
      "Could not load GitHub egress proxy token",
      { cause: error instanceof Error ? error.message : String(error) },
    );
  }
  const key = proxyUrl + "\n" + token;
  if (!cached || cached.key !== key) {
    cached = {
      key,
      fetchImpl: createTrustedGitHubFetch({ proxyUrl, proxyToken: token }),
    };
  }
  return cached.fetchImpl(input, init);
}) as typeof fetch;

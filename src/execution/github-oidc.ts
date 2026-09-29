import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
} from "node:crypto";
import { ControllerError } from "../lib/errors.js";

const ISSUER = "https://token.actions.githubusercontent.com";
const DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration";
export const AWF_OIDC_AUDIENCE = "urn:autonomous-worker-controller";

interface OidcDiscovery {
  issuer: string;
  jwks_uri: string;
}

interface JwksDocument {
  keys: Array<JsonWebKey & { kid?: string; alg?: string; use?: string }>;
}

export interface GitHubOidcClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  exp: number;
  nbf?: number;
  iat: number;
  repository: string;
  repository_visibility: string;
  workflow_ref: string;
  workflow_sha: string;
  run_id: string;
  run_attempt: string;
  runner_environment: string;
  event_name: string;
  ref: string;
}

function decodeJson(segment: string, label: string): Record<string, unknown> {
  try {
    return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    throw new ControllerError(
      "GITHUB_OIDC_INVALID",
      "GitHub OIDC " + label + " is not valid base64url JSON",
    );
  }
}

function audienceContains(aud: unknown, expected: string): boolean {
  return aud === expected || (Array.isArray(aud) && aud.includes(expected));
}

function workflowRef(
  workerRepo: string,
  workflow: string,
  dispatchRef: string,
): string {
  const ref = dispatchRef.startsWith("refs/")
    ? dispatchRef
    : "refs/heads/" + dispatchRef;
  return workerRepo + "/.github/workflows/" + workflow + "@" + ref;
}

export async function verifyGitHubActionsOidc(input: {
  jwt: string;
  workerRepo: string;
  workflow: string;
  dispatchRef: string;
  workflowRunId: number;
  workflowRunAttempt: number;
  workflowSha: string;
  fetch?: typeof fetch;
  now?: () => Date;
}): Promise<{ claims: GitHubOidcClaims; oidcSha256: string }> {
  const parts = input.jwt.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new ControllerError(
      "GITHUB_OIDC_INVALID",
      "GitHub OIDC token must be a compact three-part JWT",
    );
  }
  const header = decodeJson(parts[0]!, "header");
  const payload = decodeJson(parts[1]!, "payload");
  if (header.alg !== "RS256" || typeof header.kid !== "string") {
    throw new ControllerError(
      "GITHUB_OIDC_INVALID",
      "GitHub OIDC JWT must use RS256 with a key id",
    );
  }

  const fetchImpl = input.fetch ?? fetch;
  const discoveryResponse = await fetchImpl(DISCOVERY_URL, {
    headers: { Accept: "application/json" },
  });
  if (!discoveryResponse.ok) {
    throw new ControllerError(
      "GITHUB_OIDC_DISCOVERY_FAILED",
      "Could not load GitHub OIDC discovery document",
      { status: discoveryResponse.status },
    );
  }
  const discovery = (await discoveryResponse.json()) as OidcDiscovery;
  if (
    discovery.issuer !== ISSUER ||
    typeof discovery.jwks_uri !== "string" ||
    !discovery.jwks_uri.startsWith(ISSUER + "/")
  ) {
    throw new ControllerError(
      "GITHUB_OIDC_DISCOVERY_INVALID",
      "GitHub OIDC discovery document has an unexpected issuer/JWKS URI",
    );
  }
  const jwksResponse = await fetchImpl(discovery.jwks_uri, {
    headers: { Accept: "application/json" },
  });
  if (!jwksResponse.ok) {
    throw new ControllerError(
      "GITHUB_OIDC_JWKS_FAILED",
      "Could not load GitHub OIDC JWKS",
      { status: jwksResponse.status },
    );
  }
  const jwks = (await jwksResponse.json()) as JwksDocument;
  const jwk = jwks.keys?.find(
    (key) => key.kid === header.kid && key.kty === "RSA" && key.alg === "RS256",
  );
  if (!jwk) {
    throw new ControllerError(
      "GITHUB_OIDC_KEY_NOT_FOUND",
      "GitHub OIDC signing key was not found in JWKS",
      { kid: header.kid },
    );
  }
  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  const validSignature = verifySignature(
    "RSA-SHA256",
    Buffer.from(parts[0] + "." + parts[1], "utf8"),
    publicKey,
    Buffer.from(parts[2]!, "base64url"),
  );
  if (!validSignature) {
    throw new ControllerError(
      "GITHUB_OIDC_SIGNATURE_INVALID",
      "GitHub OIDC JWT signature verification failed",
    );
  }

  const claims = payload as unknown as GitHubOidcClaims;
  const now = Math.floor((input.now ?? (() => new Date()))().getTime() / 1000);
  const expectedWorkflowRef = workflowRef(
    input.workerRepo,
    input.workflow,
    input.dispatchRef,
  );
  if (
    claims.iss !== ISSUER ||
    !audienceContains(claims.aud, AWF_OIDC_AUDIENCE) ||
    !Number.isInteger(claims.exp) ||
    claims.exp <= now ||
    !Number.isInteger(claims.iat) ||
    claims.iat > now + 60 ||
    (claims.nbf !== undefined && claims.nbf > now + 60) ||
    claims.repository !== input.workerRepo ||
    claims.repository_visibility !== "public" ||
    claims.workflow_ref !== expectedWorkflowRef ||
    claims.workflow_sha !== input.workflowSha ||
    claims.run_id !== String(input.workflowRunId) ||
    claims.run_attempt !== String(input.workflowRunAttempt) ||
    claims.runner_environment !== "github-hosted" ||
    claims.event_name !== "workflow_dispatch" ||
    claims.ref !==
      (input.dispatchRef.startsWith("refs/")
        ? input.dispatchRef
        : "refs/heads/" + input.dispatchRef)
  ) {
    throw new ControllerError(
      "GITHUB_OIDC_CLAIMS_MISMATCH",
      "GitHub OIDC claims do not match the dispatched github-hosted workflow run",
      {
        repository: claims.repository,
        workflow_ref: claims.workflow_ref,
        workflow_sha: claims.workflow_sha,
        run_id: claims.run_id,
        run_attempt: claims.run_attempt,
        runner_environment: claims.runner_environment,
        event_name: claims.event_name,
        ref: claims.ref,
      },
    );
  }
  return {
    claims,
    oidcSha256: createHash("sha256").update(input.jwt, "utf8").digest("hex"),
  };
}

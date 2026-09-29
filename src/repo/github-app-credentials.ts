import {
  createPrivateKey,
  sign as cryptoSign,
} from "node:crypto";
import {
  lstatSync,
  readFileSync,
  realpathSync,
} from "node:fs";
import { isAbsolute } from "node:path";
import { ControllerError } from "../lib/errors.js";
import {
  GITHUB_API_VERSION,
  type GitHubInstallationCredential,
  type GitHubInstallationTokenProvider,
} from "./github-write.js";

const API_BASE = "https://api.github.com";
const SAFE_REPO_ID = /^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/;

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function parseRepoId(repoId: string): { owner: string; repo: string } {
  const match = SAFE_REPO_ID.exec(repoId);
  if (!match) {
    throw new ControllerError(
      "REPO_SOURCE_INVALID",
      "repo_id is not a safe GitHub owner/repo id",
    );
  }
  return { owner: match[1]!, repo: match[2]! };
}

export interface GitHubAppJwtSigner {
  sign(now: Date): string;
}

export interface FileGitHubAppJwtSignerOptions {
  clientId: string;
  privateKeyPath: string;
}

export class FileGitHubAppJwtSigner implements GitHubAppJwtSigner {
  readonly #clientId: string;
  readonly #privateKeyPath: string;

  constructor(options: FileGitHubAppJwtSignerOptions) {
    if (!/^[A-Za-z0-9_-]{3,128}$/.test(options.clientId)) {
      throw new ControllerError(
        "GITHUB_APP_CLIENT_ID_INVALID",
        "GitHub App client id is invalid",
      );
    }
    if (!isAbsolute(options.privateKeyPath)) {
      throw new ControllerError(
        "GITHUB_APP_PRIVATE_KEY_PATH_INVALID",
        "GitHub App private key path must be absolute",
      );
    }
    this.#clientId = options.clientId;
    this.#privateKeyPath = options.privateKeyPath;
  }

  sign(now: Date): string {
    const originalInfo = lstatSync(this.#privateKeyPath);
    if (!originalInfo.isFile() || originalInfo.isSymbolicLink()) {
      throw new ControllerError(
        "GITHUB_APP_PRIVATE_KEY_INVALID",
        "GitHub App private key must be a real regular file",
      );
    }
    if ((originalInfo.mode & 0o077) !== 0) {
      throw new ControllerError(
        "GITHUB_APP_PRIVATE_KEY_PERMISSIONS_INVALID",
        "GitHub App private key must not be accessible by group/other",
        { mode: (originalInfo.mode & 0o777).toString(8) },
      );
    }

    const resolved = realpathSync(this.#privateKeyPath);
    const resolvedInfo = lstatSync(resolved);
    if (!resolvedInfo.isFile() || resolvedInfo.isSymbolicLink()) {
      throw new ControllerError(
        "GITHUB_APP_PRIVATE_KEY_INVALID",
        "Resolved GitHub App private key must be a real regular file",
      );
    }

    const key = createPrivateKey(readFileSync(resolved));
    if (key.asymmetricKeyType !== "rsa" && key.asymmetricKeyType !== "rsa-pss") {
      throw new ControllerError(
        "GITHUB_APP_PRIVATE_KEY_INVALID",
        "GitHub App private key must be an RSA private key",
      );
    }

    const nowSeconds = Math.floor(now.getTime() / 1000);
    const header = base64UrlJson({ alg: "RS256", typ: "JWT" });
    const payload = base64UrlJson({
      iat: nowSeconds - 60,
      exp: nowSeconds + 9 * 60,
      iss: this.#clientId,
    });
    const signingInput = header + "." + payload;
    const signature = cryptoSign(
      "RSA-SHA256",
      Buffer.from(signingInput, "utf8"),
      key,
    ).toString("base64url");

    return signingInput + "." + signature;
  }
}

interface InstallationResponse {
  id: number;
  app_id?: number;
  account?: {
    login?: string;
  };
}

interface InstallationTokenResponse {
  token: string;
  expires_at: string;
}

export interface GitHubAppInstallationTokenProviderOptions {
  signer: GitHubAppJwtSigner;
  fetch?: typeof fetch;
  permissions?: {
    contents?: "read" | "write";
    pull_requests?: "read" | "write";
    checks?: "read" | "write";
    statuses?: "read" | "write";
    actions?: "read" | "write";
  };
}

export class GitHubAppInstallationTokenProvider
  implements GitHubInstallationTokenProvider
{
  readonly #signer: GitHubAppJwtSigner;
  readonly #fetch: typeof fetch;
  readonly #permissions: {
    contents?: "read" | "write";
    pull_requests?: "read" | "write";
    checks?: "read" | "write";
    statuses?: "read" | "write";
    actions?: "read" | "write";
  };

  constructor(options: GitHubAppInstallationTokenProviderOptions) {
    this.#signer = options.signer;
    this.#fetch = options.fetch ?? fetch;
    this.#permissions = options.permissions ?? {
      contents: "write",
      pull_requests: "write",
      checks: "read",
      statuses: "read",
    };
  }

  async issueForRepo(repoId: string): Promise<GitHubInstallationCredential> {
    const { owner, repo } = parseRepoId(repoId);
    const appJwt = this.#signer.sign(new Date());

    const installationResponse = await this.#fetch(
      API_BASE +
        "/repos/" +
        encodeURIComponent(owner) +
        "/" +
        encodeURIComponent(repo) +
        "/installation",
      {
        method: "GET",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: "Bearer " + appJwt,
          "X-GitHub-Api-Version": GITHUB_API_VERSION,
          "User-Agent": "autonomous-worker-controller/0.1",
        },
      },
    );
    if (!installationResponse.ok) {
      throw new ControllerError(
        "GITHUB_APP_INSTALLATION_LOOKUP_FAILED",
        "Could not resolve GitHub App installation for repository",
        {
          repoId,
          status: installationResponse.status,
          response: (await installationResponse.text()).slice(0, 4096),
        },
      );
    }
    const installation =
      (await installationResponse.json()) as InstallationResponse;
    if (!Number.isInteger(installation.id) || installation.id <= 0) {
      throw new ControllerError(
        "GITHUB_APP_INSTALLATION_INVALID",
        "GitHub installation lookup returned an invalid installation id",
      );
    }

    const tokenResponse = await this.#fetch(
      API_BASE +
        "/app/installations/" +
        String(installation.id) +
        "/access_tokens",
      {
        method: "POST",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: "Bearer " + appJwt,
          "X-GitHub-Api-Version": GITHUB_API_VERSION,
          "User-Agent": "autonomous-worker-controller/0.1",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          repositories: [repo],
          permissions: this.#permissions,
        }),
      },
    );
    if (!tokenResponse.ok) {
      throw new ControllerError(
        "GITHUB_APP_TOKEN_ISSUE_FAILED",
        "Could not create scoped GitHub App installation token",
        {
          repoId,
          installationId: installation.id,
          status: tokenResponse.status,
          response: (await tokenResponse.text()).slice(0, 4096),
        },
      );
    }

    const token = (await tokenResponse.json()) as InstallationTokenResponse;
    if (
      typeof token.token !== "string" ||
      token.token.length === 0 ||
      typeof token.expires_at !== "string" ||
      !Number.isFinite(Date.parse(token.expires_at))
    ) {
      throw new ControllerError(
        "GITHUB_APP_TOKEN_INVALID",
        "GitHub App installation-token response is invalid",
      );
    }

    return {
      token: token.token,
      expires_at: token.expires_at,
      installation_id: installation.id,
    };
  }
}

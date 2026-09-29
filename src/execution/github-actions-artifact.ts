import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { ControllerError } from "../lib/errors.js";

const execFileAsync = promisify(execFile);
const ALLOWED = new Set([
  "result-manifest.json",
  "candidate.patch",
  "verification-report.json",
  "oidc.jwt",
]);
const MAX_ARTIFACT_BYTES = 40 * 1024 * 1024;

export interface GitHubActionsResultArtifact {
  manifestJson: string;
  patchBytes: Uint8Array;
  verificationReportJson: string;
  oidcJwt: string;
}

async function unzipText(zipPath: string, name: string): Promise<Buffer> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/unzip", ["-p", zipPath, name], {
      encoding: "buffer",
      timeout: 30_000,
      maxBuffer: MAX_ARTIFACT_BYTES,
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
    });
    return Buffer.from(stdout);
  } catch (error) {
    const value = error as { stderr?: Buffer | string; message?: string };
    throw new ControllerError(
      "GITHUB_ACTIONS_ARTIFACT_INVALID",
      "Could not read expected file from GitHub Actions artifact",
      {
        name,
        stderr: value.stderr ? Buffer.from(value.stderr).toString("utf8").slice(-2048) : "",
        cause: value.message ?? String(error),
      },
    );
  }
}

export async function parseGitHubActionsResultArtifact(
  zipBytes: Uint8Array,
): Promise<GitHubActionsResultArtifact> {
  if (zipBytes.byteLength === 0 || zipBytes.byteLength > MAX_ARTIFACT_BYTES) {
    throw new ControllerError(
      "GITHUB_ACTIONS_ARTIFACT_INVALID",
      "GitHub Actions artifact size is outside the accepted bound",
      { bytes: zipBytes.byteLength, maxBytes: MAX_ARTIFACT_BYTES },
    );
  }
  const root = await mkdtemp(join(tmpdir(), "awf-gha-artifact-"));
  const zipPath = join(root, "artifact.zip");
  try {
    await writeFile(zipPath, zipBytes, { mode: 0o600 });
    const { stdout } = await execFileAsync("/usr/bin/unzip", ["-Z1", zipPath], {
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" },
    });
    const names = stdout.split("\n").filter(Boolean);
    if (
      names.length !== ALLOWED.size ||
      names.some((name) => !ALLOWED.has(name)) ||
      [...ALLOWED].some((name) => !names.includes(name))
    ) {
      throw new ControllerError(
        "GITHUB_ACTIONS_ARTIFACT_INVALID",
        "Result artifact must contain exactly the trusted AWF file set",
        { names },
      );
    }
    const [manifest, patch, verification, oidc] = await Promise.all([
      unzipText(zipPath, "result-manifest.json"),
      unzipText(zipPath, "candidate.patch"),
      unzipText(zipPath, "verification-report.json"),
      unzipText(zipPath, "oidc.jwt"),
    ]);
    if (patch.byteLength === 0) {
      throw new ControllerError(
        "GITHUB_ACTIONS_ARTIFACT_INVALID",
        "Candidate patch artifact is empty",
      );
    }
    return {
      manifestJson: manifest.toString("utf8"),
      patchBytes: new Uint8Array(patch),
      verificationReportJson: verification.toString("utf8"),
      oidcJwt: oidc.toString("utf8").trim(),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

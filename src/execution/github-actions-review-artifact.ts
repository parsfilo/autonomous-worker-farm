import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { ControllerError } from "../lib/errors.js";

const execFileAsync = promisify(execFile);
const ALLOWED = new Set(["independent-review-report.json", "oidc.jwt"]);
const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;

export interface GitHubActionsReviewArtifact {
  reportJson: string;
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
    throw new ControllerError(
      "GITHUB_ACTIONS_REVIEW_ARTIFACT_INVALID",
      "Could not read expected review artifact file",
      { name, cause: error instanceof Error ? error.message : String(error) },
    );
  }
}

export async function parseGitHubActionsReviewArtifact(
  zipBytes: Uint8Array,
): Promise<GitHubActionsReviewArtifact> {
  if (zipBytes.byteLength === 0 || zipBytes.byteLength > MAX_ARTIFACT_BYTES) {
    throw new ControllerError(
      "GITHUB_ACTIONS_REVIEW_ARTIFACT_INVALID",
      "Review artifact size is outside the accepted bound",
      { bytes: zipBytes.byteLength, maxBytes: MAX_ARTIFACT_BYTES },
    );
  }
  const root = await mkdtemp(join(tmpdir(), "awf-gha-review-artifact-"));
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
        "GITHUB_ACTIONS_REVIEW_ARTIFACT_INVALID",
        "Review artifact must contain exactly the trusted AWF review file set",
        { names },
      );
    }
    const [report, oidc] = await Promise.all([
      unzipText(zipPath, "independent-review-report.json"),
      unzipText(zipPath, "oidc.jwt"),
    ]);
    return {
      reportJson: report.toString("utf8"),
      oidcJwt: oidc.toString("utf8").trim(),
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

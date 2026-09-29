import {
  chmod,
  lstat,
  readdir,
} from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { ControllerError } from "../lib/errors.js";

interface Ownership {
  allowedUids: Set<number>;
  gid: number;
}

export interface MaterializedRepoAccessOptions {
  additionalAllowedUids?: number[];
}

function invalid(code: string, message: string, details?: Record<string, unknown>): never {
  throw new ControllerError(code, message, details);
}

async function walkAndNormalize(
  current: string,
  repoRoot: string,
  ownership: Ownership,
  gitMetadata: boolean,
): Promise<void> {
  const entries = await readdir(current, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(current, entry.name);
    const relative = path.slice(repoRoot.length + 1).replaceAll("\\", "/");
    const info = await lstat(path);

    if (info.isSymbolicLink()) {
      invalid(
        "REPO_SYMLINK_UNSUPPORTED",
        "Phase-1 worker materialization rejects repository symlinks",
        { path: relative },
      );
    }
    if (!ownership.allowedUids.has(info.uid) || info.gid !== ownership.gid) {
      invalid(
        "REPO_OWNERSHIP_INVALID",
        "Materialized repository entry ownership differs from broker-issued repo root",
        {
          path: relative,
          allowedUids: [...ownership.allowedUids],
          expectedGid: ownership.gid,
          actualUid: info.uid,
          actualGid: info.gid,
        },
      );
    }

    const isGit = gitMetadata || relative === ".git" || relative.startsWith(".git/");
    if (info.isDirectory()) {
      await chmod(path, isGit ? 0o750 : 0o770);
      await walkAndNormalize(path, repoRoot, ownership, isGit);
      continue;
    }
    if (info.isFile()) {
      const executable = (info.mode & 0o111) !== 0;
      await chmod(path, isGit ? 0o640 : executable ? 0o770 : 0o660);
      continue;
    }

    invalid(
      "REPO_SPECIAL_FILE_UNSUPPORTED",
      "Phase-1 worker materialization only supports regular files and directories",
      { path: relative },
    );
  }
}

/**
 * Normalize a materialized checkout for the unprivileged worker identity.
 *
 * The broker issues repo/ owned by the Controller UID/GID. Materializers may
 * preserve restrictive source modes (for example cp -a from a 0700 temp tree)
 * or Git may create read-only group modes. Before worker launch, make the
 * worktree group-readable/writable while keeping .git group-read-only.
 *
 * Phase-1 rejects symlinks and special files rather than trying to prove
 * resolution safety across the /run control/artifact mount boundary.
 */
export async function prepareMaterializedRepoForWorker(
  repoPath: string,
  options: MaterializedRepoAccessOptions = {},
): Promise<void> {
  if (!isAbsolute(repoPath)) {
    invalid(
      "REPO_DESTINATION_INVALID",
      "Materialized worker repository path must be absolute",
      { repoPath },
    );
  }

  const root = await lstat(repoPath);
  if (!root.isDirectory() || root.isSymbolicLink()) {
    invalid(
      "REPO_DESTINATION_INVALID",
      "Materialized worker repository must be a real directory",
      { repoPath },
    );
  }

  const ownership: Ownership = {
    allowedUids: new Set([root.uid, ...(options.additionalAllowedUids ?? [])]),
    gid: root.gid,
  };
  // Do not chmod repoPath itself. The privileged broker owns the top-level
  // lease mode (2770 + setgid) and re-validates it before provisioning.
  // A non-root Controller cannot safely recreate that setgid bit on this host.
  await walkAndNormalize(repoPath, repoPath, ownership, false);

  const gitPath = join(repoPath, ".git");
  const git = await lstat(gitPath).catch(() => null);
  if (!git || !git.isDirectory() || git.isSymbolicLink()) {
    invalid(
      "REPO_GIT_METADATA_INVALID",
      "Materialized repository must contain a real .git directory",
    );
  }
  // walkAndNormalize already made .git read-only to the worker group.
  const normalizedGit = await lstat(gitPath);
  if ((normalizedGit.mode & 0o777) !== 0o750) {
    invalid(
      "REPO_GIT_METADATA_INVALID",
      "Materialized .git directory mode normalization failed",
    );
  }
}

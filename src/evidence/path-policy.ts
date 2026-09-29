import { posix } from "node:path";
import { minimatch } from "minimatch";
import type { RepoPassport, TaskSpec } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";

export interface PathPolicyResult {
  normalizedPaths: string[];
  protectedPathsTouched: string[];
}

function matches(path: string, patterns: string[]): boolean {
  return patterns.some((pattern) =>
    minimatch(path, pattern, {
      dot: true,
      nocase: false,
      nocomment: true,
      nonegate: true,
      matchBase: false,
    }),
  );
}

export function normalizeRepoPath(input: string): string {
  if (!input || input.includes("\0") || input.includes("\\")) {
    throw new ControllerError("INVALID_REPO_PATH", "Repository path contains invalid characters", { path: input });
  }
  if (input.startsWith("/")) {
    throw new ControllerError("INVALID_REPO_PATH", "Repository path must be relative", { path: input });
  }

  const normalized = posix.normalize(input);
  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    normalized.includes("/../") ||
    normalized !== input
  ) {
    throw new ControllerError("INVALID_REPO_PATH", "Repository path is not canonical", {
      path: input,
      normalized,
    });
  }
  return normalized;
}

export function verifyChangedPathPolicy(
  task: TaskSpec,
  passport: RepoPassport,
  changedFiles: string[],
): PathPolicyResult {
  const normalizedPaths = [...new Set(changedFiles.map(normalizeRepoPath))].sort();
  const protectedPathsTouched: string[] = [];

  for (const path of normalizedPaths) {
    if (matches(path, task.denied_paths)) {
      throw new ControllerError("DENIED_PATH_CHANGED", "Candidate modified a denied path", { path });
    }

    if (!matches(path, task.write_scope)) {
      throw new ControllerError("WRITE_SCOPE_VIOLATION", "Candidate modified a path outside write_scope", {
        path,
        writeScope: task.write_scope,
      });
    }

    const protectedByPassport = matches(path, passport.protected_paths);
    const protectedByTask = matches(path, task.protected_paths);
    if (protectedByPassport || protectedByTask) {
      protectedPathsTouched.push(path);
      if (task.risk_class !== "PROTECTED" || !task.review_policy.human_approval_required) {
        throw new ControllerError(
          "PROTECTED_PATH_REQUIRES_ELEVATION",
          "Protected path changes require PROTECTED risk and human approval",
          { path },
        );
      }
    }
  }

  return { normalizedPaths, protectedPathsTouched };
}

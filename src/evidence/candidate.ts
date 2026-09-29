import { createHash } from "node:crypto";
import type { CandidateDescriptor, ResultManifest, TaskSpec } from "../../contracts/types.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

export function sha256Bytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function buildCandidateDescriptor(task: TaskSpec, manifest: ResultManifest): CandidateDescriptor {
  if (!manifest.patch_sha256) {
    throw new ControllerError("PATCH_HASH_MISSING", "Successful candidate requires patch_sha256");
  }

  const changedFiles = [...new Set(manifest.changed_files)].sort();
  if (changedFiles.length === 0) {
    throw new ControllerError("EMPTY_CANDIDATE", "Candidate contains no changed files");
  }

  return {
    schema_version: "1.0",
    repo_id: task.repo_id,
    base_sha: manifest.base_sha,
    patch_sha256: manifest.patch_sha256,
    changed_files: changedFiles,
  };
}

export function computeCandidateHash(descriptor: CandidateDescriptor): string {
  return sha256CanonicalJson({
    ...descriptor,
    changed_files: [...descriptor.changed_files].sort(),
  });
}

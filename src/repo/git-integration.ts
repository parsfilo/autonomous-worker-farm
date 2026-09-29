import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import type { GitIntegrationArtifact, TaskSpec } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import {
  buildCandidateDescriptor,
  computeCandidateHash,
  sha256Bytes,
} from "../evidence/candidate.js";
import {
  collectGitCandidate,
  type CandidateEvidence,
} from "../execution/claimed-attempt-executor.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";
import { materializeGitHubPublicRepo } from "./github-public.js";
import { prepareMaterializedRepoForWorker } from "./workspace-access.js";
import type { StoredAttempt, StoredRepoSource } from "../store/file-store.js";

const execFileAsync = promisify(execFile);
const GIT_SHA = /^[0-9a-f]{40}$/;
const FIXED_TIMESTAMP = "2000-01-01T00:00:00Z" as const;

export interface GitCommitIdentity {
  name: string;
  email: string;
}

function verifyRepoOwnedIdentity(
  repoId: string,
  identity: GitCommitIdentity,
): void {
  const owner = repoId.split("/", 1)[0] ?? "";
  const name = identity.name.trim();
  const email = identity.email.trim().toLowerCase();
  const ownerLower = owner.toLowerCase();
  const legacy = ownerLower + "@users.noreply.github.com";
  const modernSuffix = "+" + ownerLower + "@users.noreply.github.com";
  if (
    !owner ||
    name.toLowerCase() !== ownerLower ||
    !(email === legacy || (/^[0-9]+\+/.test(email) && email.endsWith(modernSuffix)))
  ) {
    throw new ControllerError(
      "GIT_INTEGRATION_IDENTITY_MISMATCH",
      "Git integration identity must belong to the target repository owner",
      { repoId, owner, name, email },
    );
  }
}

const SAFE_ENV = {
  PATH: "/usr/bin:/bin",
  LANG: "C.UTF-8",
  HOME: "/nonexistent",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_TERMINAL_PROMPT: "0",
};

async function git(
  args: string[],
  cwd: string,
  extraEnv: Record<string, string> = {},
): Promise<string> {
  try {
    const { stdout } = await execFileAsync("/usr/bin/git", args, {
      cwd,
      timeout: 60_000,
      maxBuffer: 16 * 1024 * 1024,
      env: { ...SAFE_ENV, ...extraEnv },
    });
    return stdout;
  } catch (error) {
    const value = error as { stderr?: string; message?: string };
    throw new ControllerError("GIT_INTEGRATION_COMMAND_FAILED", "Trusted Git integration command failed", {
      argv: args,
      stderr: value.stderr?.slice(-4096) ?? "",
      cause: value.message ?? String(error),
    });
  }
}

function sorted(values: string[]): string[] {
  return [...values].sort();
}

function equalStrings(a: string[], b: string[]): boolean {
  return JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));
}

function artifactHash(
  artifact: Omit<GitIntegrationArtifact, "artifact_hash"> | GitIntegrationArtifact,
): string {
  const { artifact_hash: _ignored, ...body } = artifact as GitIntegrationArtifact;
  return sha256CanonicalJson(body);
}

export function finalizeGitIntegrationArtifact(
  body: Omit<GitIntegrationArtifact, "artifact_hash">,
  contracts = new ContractRegistry(),
): GitIntegrationArtifact {
  const artifact: GitIntegrationArtifact = {
    ...body,
    artifact_hash: artifactHash(body),
  };
  return contracts.validate<GitIntegrationArtifact>("git-integration-artifact", artifact);
}

export function verifyGitIntegrationArtifact(
  artifact: GitIntegrationArtifact,
  contracts = new ContractRegistry(),
): GitIntegrationArtifact {
  contracts.validate<GitIntegrationArtifact>("git-integration-artifact", artifact);
  verifyRepoOwnedIdentity(artifact.repo_id, artifact.author);
  verifyRepoOwnedIdentity(artifact.repo_id, artifact.committer);
  if (artifact.author.name !== artifact.committer.name || artifact.author.email !== artifact.committer.email) {
    throw new ControllerError(
      "GIT_INTEGRATION_IDENTITY_MISMATCH",
      "Git integration author and committer identities must match",
    );
  }
  if (artifact.artifact_hash !== artifactHash(artifact)) {
    throw new ControllerError("GIT_INTEGRATION_ARTIFACT_HASH_MISMATCH", "Git integration artifact hash mismatch");
  }
  if (!equalStrings(artifact.changed_files, [...new Set(artifact.changed_files)])) {
    throw new ControllerError("GIT_INTEGRATION_CHANGED_FILES_INVALID", "Integration artifact changed_files must be unique");
  }
  return artifact;
}

export interface PrepareGitIntegrationInput {
  source: StoredRepoSource;
  task: TaskSpec;
  attempt: StoredAttempt;
  destination: string;
  identity: GitCommitIdentity;
  materialize?: typeof materializeGitHubPublicRepo;
  collectCandidate?: (repoPath: string, expectedBaseSha: string) => Promise<CandidateEvidence>;
}

export async function prepareGitIntegrationArtifact(
  input: PrepareGitIntegrationInput,
): Promise<GitIntegrationArtifact> {
  const { task, attempt } = input;
  verifyRepoOwnedIdentity(task.repo_id, input.identity);
  const manifest = attempt.result_manifest;
  if (
    attempt.task_id !== task.task_id ||
    attempt.state !== "CANDIDATE" ||
    !manifest ||
    !attempt.patch_path
  ) {
    throw new ControllerError(
      "GIT_INTEGRATION_NOT_READY",
      "Integration requires the exact persisted CANDIDATE attempt and patch evidence",
    );
  }
  if (
    manifest.task_id !== task.task_id ||
    manifest.attempt_id !== attempt.attempt_id ||
    manifest.base_sha !== task.base_sha ||
    !manifest.patch_sha256
  ) {
    throw new ControllerError("GIT_INTEGRATION_BINDING_MISMATCH", "Candidate manifest is not bound to the integration task");
  }

  const materialize = input.materialize ?? materializeGitHubPublicRepo;
  const collectCandidate = input.collectCandidate ?? collectGitCandidate;
  const materialized = await materialize(input.source, task, input.destination);
  if (materialized.head_sha !== task.base_sha || materialized.remote_removed !== true) {
    throw new ControllerError("GIT_INTEGRATION_BASE_MISMATCH", "Fresh integration checkout did not preserve exact base binding");
  }
  await prepareMaterializedRepoForWorker(input.destination);

  const patchBytes = await readFile(attempt.patch_path);
  if (sha256Bytes(patchBytes) !== manifest.patch_sha256) {
    throw new ControllerError("GIT_INTEGRATION_PATCH_HASH_MISMATCH", "Candidate patch changed before integration");
  }

  await git(["apply", "--check", "--binary", attempt.patch_path], input.destination);
  await git(["apply", "--binary", "--whitespace=nowarn", attempt.patch_path], input.destination);
  await prepareMaterializedRepoForWorker(input.destination);

  const reproduced = await collectCandidate(input.destination, task.base_sha);
  const reproducedPatchSha = sha256Bytes(reproduced.patchBytes);
  if (
    reproduced.headSha !== task.base_sha ||
    reproducedPatchSha !== manifest.patch_sha256 ||
    !equalStrings(reproduced.changedFiles, manifest.changed_files)
  ) {
    throw new ControllerError(
      "GIT_INTEGRATION_CANDIDATE_MISMATCH",
      "Fresh integration workspace did not reproduce the exact candidate",
      {
        expectedPatchSha: manifest.patch_sha256,
        actualPatchSha: reproducedPatchSha,
        expectedChangedFiles: sorted(manifest.changed_files),
        actualChangedFiles: sorted(reproduced.changedFiles),
      },
    );
  }

  const candidateHash = computeCandidateHash(
    buildCandidateDescriptor(task, {
      ...manifest,
      patch_sha256: reproducedPatchSha,
      changed_files: reproduced.changedFiles,
    }),
  );
  if (candidateHash !== manifest.candidate_hash) {
    throw new ControllerError("GIT_INTEGRATION_CANDIDATE_MISMATCH", "Reproduced candidate hash differs from Controller evidence");
  }

  await git(["add", "-A", "--", "."], input.destination);
  const staged = (await git(["diff", "--cached", "--name-only", "-z", "HEAD", "--"], input.destination))
    .split("\0")
    .filter(Boolean)
    .map((value) => value.replaceAll("\\", "/"));
  if (!equalStrings(staged, manifest.changed_files)) {
    throw new ControllerError("GIT_INTEGRATION_STAGED_SET_MISMATCH", "Staged Git tree differs from candidate changed_files");
  }

  const treeSha = (await git(["write-tree"], input.destination)).trim().toLowerCase();
  if (!GIT_SHA.test(treeSha)) {
    throw new ControllerError("GIT_INTEGRATION_TREE_INVALID", "Git write-tree did not return a canonical SHA-1 object id");
  }

  const message = "awf: candidate " + manifest.candidate_hash + "\n";
  const identityEnv = {
    GIT_AUTHOR_NAME: input.identity.name,
    GIT_AUTHOR_EMAIL: input.identity.email,
    GIT_AUTHOR_DATE: FIXED_TIMESTAMP,
    GIT_COMMITTER_NAME: input.identity.name,
    GIT_COMMITTER_EMAIL: input.identity.email,
    GIT_COMMITTER_DATE: FIXED_TIMESTAMP,
  };
  const commitSha = (
    await git(
      ["commit-tree", treeSha, "-p", task.base_sha, "-m", message.trimEnd()],
      input.destination,
      identityEnv,
    )
  )
    .trim()
    .toLowerCase();
  if (!GIT_SHA.test(commitSha)) {
    throw new ControllerError("GIT_INTEGRATION_COMMIT_INVALID", "Git commit-tree did not return a canonical SHA-1 object id");
  }

  const commitObject = await git(["cat-file", "-p", commitSha], input.destination);
  if (!commitObject.startsWith("tree " + treeSha + "\nparent " + task.base_sha + "\n")) {
    throw new ControllerError("GIT_INTEGRATION_COMMIT_BINDING_MISMATCH", "Commit object is not bound to expected tree/base parent");
  }

  return finalizeGitIntegrationArtifact({
    schema_version: "1.0",
    strategy: "deterministic-commit-v1",
    task_id: task.task_id,
    attempt_id: attempt.attempt_id,
    repo_id: task.repo_id,
    base_sha: task.base_sha,
    candidate_hash: manifest.candidate_hash,
    patch_sha256: manifest.patch_sha256,
    changed_files: sorted(manifest.changed_files),
    tree_sha: treeSha,
    commit_sha: commitSha,
    author: {
      name: input.identity.name,
      email: input.identity.email,
      timestamp: FIXED_TIMESTAMP,
    },
    committer: {
      name: input.identity.name,
      email: input.identity.email,
      timestamp: FIXED_TIMESTAMP,
    },
    message_sha256: sha256Bytes(Buffer.from(message, "utf8")),
  });
}

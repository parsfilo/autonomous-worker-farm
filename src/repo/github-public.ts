import { execFile } from "node:child_process";
import { lstat, readdir } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { promisify } from "node:util";
import type { TaskSpec } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";
import type { StoredRepoSource } from "../store/file-store.js";

const execFileAsync = promisify(execFile);
const SHA40 = /^[0-9a-f]{40}$/;
const SAFE_BRANCH = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/;

export interface GitRunResult {
  stdout: string;
  stderr: string;
}

export interface GitRunner {
  run(args: string[], cwd: string): Promise<GitRunResult>;
}

export interface MaterializeResult {
  repo_id: string;
  head_sha: string;
  remote_removed: true;
}

export class ExecGitRunner implements GitRunner {
  async run(args: string[], cwd: string): Promise<GitRunResult> {
    try {
      const { stdout, stderr } = await execFileAsync("/usr/bin/git", args, {
        cwd,
        timeout: 120_000,
        maxBuffer: 8 * 1024 * 1024,
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C.UTF-8",
          HOME: "/nonexistent",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_TERMINAL_PROMPT: "0",
          GCM_INTERACTIVE: "Never",
        },
      });
      return { stdout, stderr };
    } catch (error) {
      const value = error as {
        stdout?: string;
        stderr?: string;
        message?: string;
      };
      throw new ControllerError(
        "REPO_GIT_COMMAND_FAILED",
        "Git materialization command failed",
        {
          argv: args,
          stderr: value.stderr?.slice(-4096) ?? "",
          cause: value.message ?? String(error),
        },
      );
    }
  }
}

function validateBranchName(baseRef: string): void {
  if (
    !SAFE_BRANCH.test(baseRef) ||
    baseRef.startsWith("-") ||
    baseRef.includes("..") ||
    baseRef.includes("//") ||
    baseRef.includes("@{") ||
    /[\\~^:?*\[\]\x00-\x20\x7f]/.test(baseRef) ||
    baseRef.endsWith("/") ||
    baseRef.endsWith(".") ||
    baseRef.endsWith(".lock")
  ) {
    throw new ControllerError(
      "REPO_BASE_REF_INVALID",
      "base_ref is not a safe public GitHub branch name",
      { baseRef },
    );
  }
}

function expectedRemote(repoId: string): string {
  if (!/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(repoId)) {
    throw new ControllerError("REPO_SOURCE_INVALID", "repo_id is not a safe GitHub owner/repo id");
  }
  return "https://github.com/" + repoId + ".git";
}

export async function materializeGitHubPublicRepo(
  source: StoredRepoSource,
  task: TaskSpec,
  destination: string,
  runner: GitRunner = new ExecGitRunner(),
): Promise<MaterializeResult> {
  if (source.kind !== "github-public" || source.repo_id !== task.repo_id) {
    throw new ControllerError(
      "REPO_SOURCE_MISMATCH",
      "Repo source is not the registered github-public source for this task",
    );
  }
  const remote = expectedRemote(task.repo_id);
  if (source.remote_url !== remote) {
    throw new ControllerError(
      "REPO_SOURCE_MISMATCH",
      "Stored public GitHub remote does not match canonical repo_id",
    );
  }
  if (!isAbsolute(destination)) {
    throw new ControllerError("REPO_DESTINATION_INVALID", "Repository destination must be absolute");
  }
  if (!SHA40.test(task.base_sha)) {
    throw new ControllerError("REPO_BASE_SHA_INVALID", "base_sha must be lowercase 40-hex");
  }
  validateBranchName(task.base_ref);

  const info = await lstat(destination);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new ControllerError(
      "REPO_DESTINATION_INVALID",
      "Broker-issued repository destination must be a real directory",
    );
  }
  const entries = await readdir(destination);
  if (entries.length !== 0) {
    throw new ControllerError(
      "REPO_DESTINATION_NOT_EMPTY",
      "Broker-issued repository destination must be empty before materialization",
    );
  }

  await runner.run(["init", "--quiet", "--initial-branch=awf-base", "."], destination);
  await runner.run(["config", "core.hooksPath", "/dev/null"], destination);
  await runner.run(["remote", "add", "origin", remote], destination);
  await runner.run(["check-ref-format", "--branch", task.base_ref], destination);
  await runner.run(
    [
      "-c",
      "credential.helper=",
      "-c",
      "protocol.version=2",
      "fetch",
      "--quiet",
      "--no-tags",
      "--depth=1",
      "origin",
      "refs/heads/" + task.base_ref,
    ],
    destination,
  );

  const fetched = (
    await runner.run(["rev-parse", "--verify", "FETCH_HEAD^{commit}"], destination)
  ).stdout.trim().toLowerCase();
  if (fetched !== task.base_sha) {
    throw new ControllerError(
      "BASE_DRIFT",
      "Fetched branch head does not match TaskSpec base_sha",
      { expected: task.base_sha, fetched },
    );
  }

  await runner.run(["checkout", "--quiet", "--detach", task.base_sha, "--"], destination);
  await runner.run(["remote", "remove", "origin"], destination);

  const head = (
    await runner.run(["rev-parse", "--verify", "HEAD^{commit}"], destination)
  ).stdout.trim().toLowerCase();
  if (head !== task.base_sha) {
    throw new ControllerError(
      "REPO_CHECKOUT_MISMATCH",
      "Materialized HEAD does not match TaskSpec base_sha",
      { expected: task.base_sha, actual: head },
    );
  }

  const status = (
    await runner.run(["status", "--porcelain=v1", "--untracked-files=all"], destination)
  ).stdout.trim();
  if (status !== "") {
    throw new ControllerError(
      "REPO_CHECKOUT_DIRTY",
      "Materialized repository is not clean before worker execution",
      { status: status.slice(0, 4096) },
    );
  }

  return {
    repo_id: task.repo_id,
    head_sha: head,
    remote_removed: true,
  };
}

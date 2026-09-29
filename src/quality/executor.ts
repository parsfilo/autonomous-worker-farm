import { execFile } from "node:child_process";
import {
  lstat,
  mkdir,
  readFile,
  realpath,
  rm,
} from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { promisify } from "node:util";
import type {
  QualityProfile,
  VerificationReport,
} from "../../contracts/types.js";
import { ControllerCore } from "../controller/controller.js";
import {
  buildCandidateDescriptor,
  computeCandidateHash,
  sha256Bytes,
} from "../evidence/candidate.js";
import {
  collectGitCandidate,
  type CandidateEvidence,
} from "../execution/claimed-attempt-executor.js";
import { ControllerError } from "../lib/errors.js";
import { materializeGitHubPublicRepo } from "../repo/github-public.js";
import type { StoredRepoSource } from "../store/file-store.js";
import {
  buildValidationPlanFromQualityProfile,
  loadQualityProfile,
} from "./profile.js";
import {
  buildVerificationReport,
} from "./verification-report.js";
import type {
  LandlockQualityCommandRunner,
  QualityCommandExecution,
} from "./landlock-runner.js";

const execFileAsync = promisify(execFile);

export interface LocalVerificationRunner {
  run(
    plan: Parameters<LandlockQualityCommandRunner["run"]>[0],
    command: Parameters<LandlockQualityCommandRunner["run"]>[1],
  ): Promise<QualityCommandExecution>;
}

export interface LocalVerificationExecutorOptions {
  core: ControllerCore;
  qualityProfileRoot: string;
  validationRoot: string;
  verifierBuild: string;
  runner: LocalVerificationRunner;
  materialize?: typeof materializeGitHubPublicRepo;
  collectCandidate?: (
    repoPath: string,
    expectedBaseSha: string,
  ) => Promise<CandidateEvidence>;
}

export interface LocalVerificationExecutionResult {
  attempt: ReturnType<ControllerCore["getAttempt"]>;
  report: VerificationReport;
}

function inside(parent: string, child: string): boolean {
  const base = resolve(parent);
  const target = resolve(child);
  return target !== base && target.startsWith(base + "/");
}

async function gitApply(patchPath: string, repoPath: string): Promise<void> {
  const env = {
    PATH: "/usr/bin:/bin",
    LANG: "C.UTF-8",
    HOME: "/nonexistent",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
  };
  try {
    await execFileAsync(
      "/usr/bin/git",
      ["apply", "--check", "--binary", patchPath],
      { cwd: repoPath, timeout: 60_000, maxBuffer: 4 * 1024 * 1024, env },
    );
    await execFileAsync(
      "/usr/bin/git",
      ["apply", "--binary", "--whitespace=nowarn", patchPath],
      { cwd: repoPath, timeout: 60_000, maxBuffer: 4 * 1024 * 1024, env },
    );
  } catch (error) {
    const value = error as { stderr?: string; message?: string };
    throw new ControllerError(
      "QUALITY_CANDIDATE_APPLY_FAILED",
      "Could not apply exact candidate patch in validation workspace",
      {
        stderr: value.stderr?.slice(-4096) ?? "",
        cause: value.message ?? String(error),
      },
    );
  }
}

function assertExactCandidate(
  task: ReturnType<ControllerCore["getTask"]>["spec"],
  manifest: NonNullable<ReturnType<ControllerCore["getAttempt"]>["result_manifest"]>,
  evidence: CandidateEvidence,
): void {
  const patchSha = sha256Bytes(evidence.patchBytes);
  if (
    evidence.headSha !== task.base_sha ||
    patchSha !== manifest.patch_sha256 ||
    JSON.stringify([...evidence.changedFiles].sort()) !==
      JSON.stringify([...manifest.changed_files].sort())
  ) {
    throw new ControllerError(
      "QUALITY_CANDIDATE_MATERIALIZATION_MISMATCH",
      "Validation workspace does not reproduce the exact candidate patch",
    );
  }
  const candidateHash = computeCandidateHash(
    buildCandidateDescriptor(task, {
      ...manifest,
      patch_sha256: patchSha,
      changed_files: evidence.changedFiles,
    }),
  );
  if (candidateHash !== manifest.candidate_hash) {
    throw new ControllerError(
      "QUALITY_CANDIDATE_MATERIALIZATION_MISMATCH",
      "Validation candidate hash does not match stored candidate evidence",
      { expected: manifest.candidate_hash, actual: candidateHash },
    );
  }
}

export class LocalVerificationExecutor {
  readonly #core: ControllerCore;
  readonly #qualityProfileRoot: string;
  readonly #validationRoot: string;
  readonly #verifierBuild: string;
  readonly #runner: LocalVerificationRunner;
  readonly #materialize: typeof materializeGitHubPublicRepo;
  readonly #collectCandidate: (
    repoPath: string,
    expectedBaseSha: string,
  ) => Promise<CandidateEvidence>;

  constructor(options: LocalVerificationExecutorOptions) {
    this.#core = options.core;
    this.#qualityProfileRoot = resolve(options.qualityProfileRoot);
    this.#validationRoot = resolve(options.validationRoot);
    this.#verifierBuild = options.verifierBuild;
    this.#runner = options.runner;
    this.#materialize = options.materialize ?? materializeGitHubPublicRepo;
    this.#collectCandidate = options.collectCandidate ?? collectGitCandidate;

    if (!isAbsolute(this.#qualityProfileRoot) || !isAbsolute(this.#validationRoot)) {
      throw new ControllerError(
        "QUALITY_EXECUTOR_CONFIG_INVALID",
        "Quality profile and validation roots must be absolute",
      );
    }
    if (!this.#verifierBuild || this.#verifierBuild.length > 256) {
      throw new ControllerError(
        "QUALITY_EXECUTOR_CONFIG_INVALID",
        "Verifier build identity is invalid",
      );
    }
  }

  async execute(attemptId: string): Promise<LocalVerificationExecutionResult> {
    const attempt = this.#core.getAttempt(attemptId);
    if (
      attempt.state !== "LOCAL_VERIFY" ||
      !attempt.result_manifest ||
      !attempt.patch_path ||
      !attempt.validation_plan
    ) {
      throw new ControllerError(
        "LOCAL_VERIFICATION_NOT_READY",
        "Attempt must have candidate evidence and be waiting in LOCAL_VERIFY",
      );
    }
    const task = this.#core.getTask(attempt.task_id).spec;
    const { passport } = this.#core.getPassport(task.repo_id);
    const source = this.#core.getRepoSource(task.repo_id);

    const profilePath = await this.#trustedProfilePath(task.quality_profile);
    const profile = loadQualityProfile(profilePath);
    const attemptRoot = join(this.#validationRoot, attemptId);
    const repoPath = join(attemptRoot, "repo");

    const rootInfo = await lstat(this.#validationRoot);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
      throw new ControllerError(
        "VALIDATION_ROOT_INVALID",
        "Validation root must be a real directory",
      );
    }

    try {
      await mkdir(attemptRoot, { mode: 0o700 });
      await mkdir(repoPath, { mode: 0o700 });

      await this.#materialize(source, task, repoPath);
      const patchBytes = await readFile(attempt.patch_path);
      if (sha256Bytes(patchBytes) !== attempt.result_manifest.patch_sha256) {
        throw new ControllerError(
          "QUALITY_PATCH_HASH_MISMATCH",
          "Candidate patch artifact changed before local verification",
        );
      }
      await gitApply(attempt.patch_path, repoPath);

      const before = await this.#collectCandidate(repoPath, task.base_sha);
      assertExactCandidate(task, attempt.result_manifest, before);

      const plan = buildValidationPlanFromQualityProfile({
        task,
        passport,
        candidateHash: attempt.result_manifest.candidate_hash,
        validationWorkspace: repoPath,
        profile,
      });
      if (
        plan.plan_id !== attempt.validation_plan.plan_id ||
        JSON.stringify(plan) !== JSON.stringify(attempt.validation_plan)
      ) {
        throw new ControllerError(
          "VALIDATION_PLAN_DRIFT",
          "Stored ValidationPlan no longer matches trusted profile/task/candidate inputs",
        );
      }
      if (
        plan.scanner_profiles.semgrep !== null ||
        plan.scanner_profiles.codacy !== null ||
        plan.scanner_profiles.sonar !== null
      ) {
        throw new ControllerError(
          "QUALITY_SCANNER_RUNNER_NOT_READY",
          "Local verifier scanner execution is not enabled yet",
          { scannerProfiles: plan.scanner_profiles },
        );
      }

      const startedAt = new Date().toISOString();
      const commandResults = [];
      for (const command of plan.commands) {
        const execution = await this.#runner.run(plan, command);
        commandResults.push(execution.result);

        const afterCommand = await this.#collectCandidate(repoPath, task.base_sha);
        try {
          assertExactCandidate(task, attempt.result_manifest, afterCommand);
        } catch (error) {
          this.#core.failAttempt(
            attemptId,
            "POLICY_VIOLATION",
            "QUALITY_WORKSPACE_MUTATED",
            execution.result.exit_code,
            { command: command.name },
          );
          throw error;
        }
      }
      const endedAt = new Date().toISOString();

      const report = buildVerificationReport(plan, {
        startedAt,
        endedAt,
        commandResults,
        gates: {},
        verifier: {
          machine_id: attempt.machine_id,
          build: this.#verifierBuild,
        },
      });
      const completed = this.#core.completeLocalVerification(attemptId, report);
      return { attempt: completed, report };
    } catch (error) {
      const current = this.#core.getAttempt(attemptId);
      if (current.state === "LOCAL_VERIFY") {
        const code = error instanceof ControllerError ? error.code : "QUALITY_EXECUTOR_FAILED";
        if (
          code === "QUALITY_CANDIDATE_APPLY_FAILED" ||
          code === "QUALITY_PATCH_HASH_MISMATCH" ||
          code === "QUALITY_CANDIDATE_MATERIALIZATION_MISMATCH" ||
          code === "VALIDATION_PLAN_DRIFT"
        ) {
          this.#core.failAttempt(
            attemptId,
            "POLICY_VIOLATION",
            code,
            null,
            { cause: error instanceof Error ? error.message : String(error) },
          );
        }
      }
      throw error;
    } finally {
      await rm(attemptRoot, { recursive: true, force: true });
    }
  }

  async #trustedProfilePath(profileId: string): Promise<string> {
    const root = await realpath(this.#qualityProfileRoot);
    const candidate = join(root, profileId + ".json");
    const resolved = await realpath(candidate);
    if (!inside(root, resolved)) {
      throw new ControllerError(
        "QUALITY_PROFILE_PATH_INVALID",
        "Trusted quality profile escaped its root",
      );
    }
    const info = await lstat(resolved);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new ControllerError(
        "QUALITY_PROFILE_PATH_INVALID",
        "Trusted quality profile must be a real file",
      );
    }
    return resolved;
  }
}

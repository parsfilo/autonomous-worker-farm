import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import type {
  GateEvidence,
  QualityProfile,
  RepoPassport,
  ResultManifest,
  TaskSpec,
  VerificationCommandResult,
} from "../contracts/types.js";
import { ContractRegistry } from "../src/contracts/schema-validator.js";
import {
  buildCandidateDescriptor,
  computeCandidateHash,
  sha256Bytes,
} from "../src/evidence/candidate.js";
import {
  collectGitCandidate,
  exactShellAllowlist,
} from "../src/execution/claimed-attempt-executor.js";
import {
  OPENCODE_FIXED_RUN_ARGV,
  renderOpenCodeTaskDocument,
} from "../src/harness/opencode/adapter.js";
import { renderOpenCodeAttemptConfig } from "../src/harness/opencode/attempt-config.js";
import { ControllerError } from "../src/lib/errors.js";
import {
  buildValidationPlanFromQualityProfile,
  validateQualityProfile,
} from "../src/quality/profile.js";
import { buildVerificationReport } from "../src/quality/verification-report.js";

const execFileAsync = promisify(execFile);
const contracts = new ContractRegistry();
const MAX_OUTPUT = 16 * 1024 * 1024;

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error("missing required environment variable: " + name);
  return value;
}

function decodeJson<T>(name: string): T {
  try {
    return JSON.parse(
      Buffer.from(requiredEnv(name), "base64url").toString("utf8"),
    ) as T;
  } catch (error) {
    throw new Error(
      "invalid base64url JSON in " +
        name +
        ": " +
        (error instanceof Error ? error.message : String(error)),
    );
  }
}

function missingGate(): GateEvidence {
  return {
    status: "MISSING",
    exit_code: null,
    report_sha256: null,
    report_uri: null,
    details: { reason: "collected by separate deterministic verifier" },
  };
}

function hash(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function git(args: string[], cwd: string): Promise<string> {
  const { stdout } = await execFileAsync("/usr/bin/git", args, {
    cwd,
    timeout: 60_000,
    maxBuffer: MAX_OUTPUT,
    encoding: "utf8",
    env: {
      PATH: "/usr/bin:/bin",
      HOME: "/nonexistent",
      LANG: "C.UTF-8",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
    },
  });
  return stdout;
}

async function prepareBaseCopy(
  source: string,
  destination: string,
  baseSha: string,
): Promise<void> {
  await mkdir(destination, { recursive: true, mode: 0o700 });
  await cp(source, destination, {
    recursive: true,
    force: false,
    errorOnExist: false,
    preserveTimestamps: true,
  });
  const head = (await git(["rev-parse", "--verify", "HEAD^{commit}"], destination))
    .trim()
    .toLowerCase();
  if (head !== baseSha) {
    throw new ControllerError("BASE_DRIFT", "GitHub Actions checkout is not at exact TaskSpec base SHA", {
      expected: baseSha,
      actual: head,
    });
  }
  const remotes = (await git(["remote"], destination))
    .trim()
    .split("\n")
    .filter(Boolean);
  for (const remote of remotes) {
    await git(["remote", "remove", remote], destination);
  }
}

async function assertExactCandidate(
  task: TaskSpec,
  manifest: ResultManifest,
  repoPath: string,
): Promise<void> {
  const evidence = await collectGitCandidate(repoPath, task.base_sha);
  const patchSha = sha256Bytes(evidence.patchBytes);
  if (
    patchSha !== manifest.patch_sha256 ||
    JSON.stringify([...evidence.changedFiles].sort()) !==
      JSON.stringify([...manifest.changed_files].sort())
  ) {
    throw new Error("verification workspace no longer reproduces exact candidate");
  }
  const candidateHash = computeCandidateHash(
    buildCandidateDescriptor(task, {
      ...manifest,
      patch_sha256: patchSha,
      changed_files: evidence.changedFiles,
    }),
  );
  if (candidateHash !== manifest.candidate_hash) {
    throw new Error("verification workspace candidate hash drift");
  }
}

async function docker(
  args: string[],
  options: {
    timeoutMs?: number;
    encoding?: "utf8" | "buffer";
  } = {},
): Promise<{ stdout: Buffer; stderr: Buffer }> {
  try {
    const result = await execFileAsync("/usr/bin/docker", args, {
      timeout: options.timeoutMs ?? 120_000,
      maxBuffer: MAX_OUTPUT,
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        HOME: "/nonexistent",
        LANG: "C.UTF-8",
        DOCKER_BUILDKIT: "1",
      },
    });
    return {
      stdout: Buffer.from(result.stdout),
      stderr: Buffer.from(result.stderr),
    };
  } catch (error) {
    const value = error as {
      code?: number | string;
      stdout?: Buffer | string;
      stderr?: Buffer | string;
      message?: string;
    };
    throw new ControllerError(
      "GITHUB_ACTIONS_DOCKER_FAILED",
      "Trusted GitHub Actions Docker command failed",
      {
        argv: args.slice(0, 24),
        exit_code: value.code ?? null,
        stdout: value.stdout
          ? Buffer.from(value.stdout).toString("utf8").slice(-4000)
          : "",
        stderr: value.stderr
          ? Buffer.from(value.stderr).toString("utf8").slice(-4000)
          : "",
        cause: value.message ?? String(error),
      },
    );
  }
}

function safeDockerImage(value: string, label: string): string {
  if (!/^[A-Za-z0-9._/@:-]{1,256}$/.test(value)) {
    throw new Error(label + " is not a safe Docker image reference");
  }
  return value;
}

async function runOpenCodeContainer(input: {
  attemptId: string;
  task: TaskSpec;
  passport: RepoPassport;
  repoPath: string;
  controlDir: string;
  artifactDir: string;
  workerImage: string;
  gatewayImage: string;
}): Promise<{ startedAt: string; endedAt: string; durationMs: number }> {
  const suffix = input.attemptId.replace(/[^A-Za-z0-9_.-]/g, "-").slice(-64);
  const workerNetwork = "awf-worker-" + suffix;
  const egressNetwork = "awf-egress-" + suffix;
  const gatewayName = "awf-gateway-" + suffix;
  const workerName = "awf-worker-" + suffix;
  const uid = process.getuid?.() ?? 1001;
  const gid = process.getgid?.() ?? 1001;

  await docker(["network", "create", "--internal", workerNetwork]);
  try {
    await docker(["network", "create", egressNetwork]);
    try {
      await docker([
        "run",
        "-d",
        "--name",
        gatewayName,
        "--network",
        egressNetwork,
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "256m",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        input.gatewayImage,
        "--mode",
        "opencode-free-connect",
        "--listen",
        ":8888",
        "--proxy-host",
        "opencode.ai",
        "--proxy-port",
        "443",
        "--max-concurrent-requests",
        "8",
      ]);
      await docker([
        "network",
        "connect",
        "--alias",
        "awf-egress",
        workerNetwork,
        gatewayName,
      ]);

      const startedMs = Date.now();
      const startedAt = new Date(startedMs).toISOString();
      try {
        await docker(
          [
            "run",
            "--rm",
            "--name",
            workerName,
            "--network",
            workerNetwork,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "256",
            "--memory",
            "4g",
            "--cpus",
            "2",
            "--tmpfs",
            "/tmp:rw,nosuid,size=512m",
            "--user",
            String(uid) + ":" + String(gid),
            "--mount",
            "type=bind,src=" + input.repoPath + ",dst=/run/repo",
            "--mount",
            "type=bind,src=" + input.controlDir + ",dst=/run/control,readonly",
            "--mount",
            "type=bind,src=" + input.artifactDir + ",dst=/run/artifacts",
            "--env",
            "HOME=/tmp/home",
            "--env",
            "XDG_CONFIG_HOME=/tmp/.config",
            "--env",
            "XDG_CACHE_HOME=/tmp/.cache",
            "--env",
            "XDG_DATA_HOME=/tmp/.local/share",
            "--env",
            "TMPDIR=/tmp",
            "--env",
            "OPENCODE_DISABLE_PROJECT_CONFIG=1",
            "--env",
            "OPENCODE_CONFIG_DIR=/run/control/opencode",
            "--env",
            "OPENCODE_DB=:memory:",
            "--env",
            "AWF_REPO_DIR=/run/repo",
            "--env",
            "AWF_ARTIFACT_DIR=/run/artifacts",
            "--env",
            "AWF_REPO_ID=" + input.passport.repo_id,
            "--env",
            "AWF_TASK_ID=" + input.task.task_id,
            "--env",
            "HTTPS_PROXY=http://awf-egress:8888",
            "--env",
            "https_proxy=http://awf-egress:8888",
            "--env",
            "HTTP_PROXY=http://awf-egress:8888",
            "--env",
            "http_proxy=http://awf-egress:8888",
            "--env",
            "NO_PROXY=127.0.0.1,localhost,::1",
            "--env",
            "no_proxy=127.0.0.1,localhost,::1",
            "--env",
            "CI=true",
            "--workdir",
            "/run",
            input.workerImage,
            ...OPENCODE_FIXED_RUN_ARGV,
          ],
          { timeoutMs: input.task.timeout_seconds * 1000 },
        );
      } catch (error) {
        try {
          await docker(["rm", "-f", workerName]);
        } catch {
          // Best-effort cleanup only.
        }
        throw error;
      }
      const endedMs = Date.now();
      return {
        startedAt,
        endedAt: new Date(endedMs).toISOString(),
        durationMs: Math.max(0, endedMs - startedMs),
      };
    } finally {
      try {
        await docker(["rm", "-f", gatewayName]);
      } catch {
        // Best-effort cleanup only.
      }
      try {
        await docker(["network", "rm", egressNetwork]);
      } catch {
        // Best-effort cleanup only.
      }
    }
  } finally {
    try {
      await docker(["network", "rm", workerNetwork]);
    } catch {
      // Best-effort cleanup only.
    }
  }
}

async function runVerificationCommand(
  name: string,
  argv: string[],
  cwd: string,
  timeoutSeconds: number,
  workerImage: string,
): Promise<VerificationCommandResult> {
  const started = Date.now();
  let exitCode = 0;
  let stdout = Buffer.alloc(0);
  let stderr = Buffer.alloc(0);
  const uid = process.getuid?.() ?? 1001;
  const gid = process.getgid?.() ?? 1001;
  try {
    const result = await execFileAsync(
      "/usr/bin/docker",
      [
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "4g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,nosuid,size=512m",
        "--user",
        String(uid) + ":" + String(gid),
        "--mount",
        "type=bind,src=" + cwd + ",dst=/workspace",
        "--env",
        "HOME=/tmp/home",
        "--env",
        "LANG=C.UTF-8",
        "--env",
        "CI=true",
        "--env",
        "GIT_CONFIG_NOSYSTEM=1",
        "--env",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "--env",
        "GIT_TERMINAL_PROMPT=0",
        "--workdir",
        "/workspace",
        workerImage,
        ...argv,
      ],
      {
        timeout: timeoutSeconds * 1000,
        maxBuffer: MAX_OUTPUT,
        encoding: "buffer",
        env: {
          PATH: "/usr/bin:/bin",
          HOME: "/nonexistent",
          LANG: "C.UTF-8",
        },
      },
    );
    stdout = Buffer.from(result.stdout);
    stderr = Buffer.from(result.stderr);
  } catch (error) {
    const value = error as {
      code?: number | string;
      stdout?: Buffer | string;
      stderr?: Buffer | string;
    };
    exitCode = typeof value.code === "number" ? value.code : 1;
    stdout = value.stdout ? Buffer.from(value.stdout) : Buffer.alloc(0);
    stderr = value.stderr ? Buffer.from(value.stderr) : Buffer.alloc(0);
  }
  return {
    name,
    argv: [...argv],
    exit_code: exitCode,
    duration_ms: Math.max(0, Date.now() - started),
    stdout_sha256: hash(stdout),
    stderr_sha256: hash(stderr),
  };
}

async function main(): Promise<void> {
  const task = contracts.validate<TaskSpec>("task-spec", decodeJson("AWF_TASK_B64"));
  const passport = contracts.validate<RepoPassport>(
    "repo-passport",
    decodeJson("AWF_PASSPORT_B64"),
  );
  const profile = validateQualityProfile(
    decodeJson<QualityProfile>("AWF_QUALITY_PROFILE_B64"),
    contracts,
  );
  const attemptId = requiredEnv("AWF_ATTEMPT_ID");
  const machineId = requiredEnv("AWF_MACHINE_ID");
  const model = requiredEnv("AWF_MODEL");
  const targetSource = resolve(requiredEnv("AWF_TARGET_CHECKOUT"));
  const outputDir = resolve(requiredEnv("AWF_OUTPUT_DIR"));
  const runnerTemp = resolve(requiredEnv("RUNNER_TEMP"));
  const workerImage = safeDockerImage(requiredEnv("AWF_WORKER_IMAGE"), "AWF_WORKER_IMAGE");
  const gatewayImage = safeDockerImage(requiredEnv("AWF_GATEWAY_IMAGE"), "AWF_GATEWAY_IMAGE");
  const opencodeVersion = requiredEnv("AWF_OPENCODE_VERSION");

  if (task.repo_id !== passport.repo_id || task.quality_profile !== profile.profile_id) {
    throw new Error("task/passport/quality profile binding mismatch");
  }
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  const runRoot = join(runnerTemp, "awf-" + attemptId);
  const repoPath = join(runRoot, "repo");
  const controlDir = join(runRoot, "control");
  const opencodeDir = join(controlDir, "opencode");
  const artifactDir = join(runRoot, "artifacts");
  await rm(runRoot, { recursive: true, force: true });
  for (const path of [controlDir, opencodeDir, artifactDir]) {
    await mkdir(path, { recursive: true, mode: 0o700 });
  }
  await prepareBaseCopy(targetSource, repoPath, task.base_sha);

  const rendered = renderOpenCodeAttemptConfig(task, passport, "/run", {
    model,
    allowedShellPatterns: exactShellAllowlist(
      passport.allowed_build_commands,
      passport.allowed_test_commands,
    ),
    approvedSkillIds: task.approved_skills.map((skill) => skill.id),
  });
  await writeFile(
    join(opencodeDir, "opencode.json"),
    JSON.stringify(rendered.config, null, 2) + "\n",
    { mode: 0o600 },
  );
  await writeFile(join(controlDir, "task.md"), renderOpenCodeTaskDocument(task), {
    mode: 0o600,
  });

  const execution = await runOpenCodeContainer({
    attemptId,
    task,
    passport,
    repoPath,
    controlDir,
    artifactDir,
    workerImage,
    gatewayImage,
  });
  const startedAt = execution.startedAt;
  const endedAt = execution.endedAt;

  const candidate = await collectGitCandidate(repoPath, task.base_sha);
  if (candidate.changedFiles.length === 0 || candidate.patchBytes.byteLength === 0) {
    throw new Error("OpenCode worker produced no candidate patch");
  }
  const patchSha = sha256Bytes(candidate.patchBytes);
  const manifest: ResultManifest = {
    schema_version: "1.0",
    task_id: task.task_id,
    attempt_id: attemptId,
    attempt_no: Number(requiredEnv("AWF_ATTEMPT_NO")),
    base_sha: task.base_sha,
    repo_passport_hash: task.repo_passport_hash,
    context_snapshot_hash: task.context_snapshot_hash,
    machine: {
      machine_id: machineId,
      os: process.platform,
    },
    sandbox: {
      tier: "T1",
      attested: true,
      landlock_abi: null,
      container_runtime: "github-actions-docker",
      container_image_digest: null,
    },
    harness: {
      adapter: "opencode",
      version: opencodeVersion,
      digest: null,
      session_id: null,
    },
    model: {
      provider: "opencode",
      model,
      request_ids: [],
    },
    approved_skills: task.approved_skills,
    tool_versions: {
      opencode: opencodeVersion,
      node: "24.19.0",
    },
    started_at: startedAt,
    ended_at: endedAt,
    status: "SUCCEEDED",
    changed_files: candidate.changedFiles,
    patch_sha256: patchSha,
    candidate_hash: "0".repeat(64),
    candidate_commit_sha: null,
    commands: [
      {
        argv: ["opencode", ...OPENCODE_FIXED_RUN_ARGV.slice(1)],
        cwd: runRoot,
        exit_code: 0,
        duration_ms: execution.durationMs,
      },
    ],
    checks: {
      format: missingGate(),
      lint: missingGate(),
      typecheck: missingGate(),
      build: missingGate(),
      secret_scan: missingGate(),
    },
    tests: [],
    lsp_diagnostics: [],
    quality: {
      semgrep: missingGate(),
      codacy: missingGate(),
      sonar: missingGate(),
    },
    policy_events: [],
    network_events: [],
    artifacts: [
      {
        name: "candidate.patch",
        uri: null,
        sha256: patchSha,
        media_type: "text/x-diff",
      },
    ],
    summary:
      "GitHub-hosted OpenCode worker produced an exact patch; deterministic verification executed separately in a fresh runner workspace copy.",
  };
  manifest.candidate_hash = computeCandidateHash(
    buildCandidateDescriptor(task, manifest),
  );
  contracts.validate<ResultManifest>("result-manifest", manifest);
  await writeFile(join(outputDir, "candidate.patch"), candidate.patchBytes, {
    mode: 0o600,
  });
  await writeFile(
    join(outputDir, "result-manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n",
    { mode: 0o600 },
  );

  const verifyRepo = join(runRoot, "verify-repo");
  await prepareBaseCopy(targetSource, verifyRepo, task.base_sha);
  await writeFile(join(runRoot, "candidate.patch"), candidate.patchBytes, {
    mode: 0o600,
  });
  await execFileAsync(
    "/usr/bin/git",
    ["apply", "--check", "--binary", join(runRoot, "candidate.patch")],
    { cwd: verifyRepo, timeout: 60_000, maxBuffer: MAX_OUTPUT },
  );
  await execFileAsync(
    "/usr/bin/git",
    ["apply", "--binary", "--whitespace=nowarn", join(runRoot, "candidate.patch")],
    { cwd: verifyRepo, timeout: 60_000, maxBuffer: MAX_OUTPUT },
  );
  await assertExactCandidate(task, manifest, verifyRepo);

  const plan = buildValidationPlanFromQualityProfile({
    task,
    passport,
    candidateHash: manifest.candidate_hash,
    validationWorkspace: verifyRepo,
    profile,
  });
  if (
    plan.scanner_profiles.semgrep !== null ||
    plan.scanner_profiles.codacy !== null ||
    plan.scanner_profiles.sonar !== null
  ) {
    throw new Error("GitHub Actions scanner profiles are not enabled yet");
  }
  const verificationStartedAt = new Date().toISOString();
  const commandResults: VerificationCommandResult[] = [];
  for (const command of plan.commands) {
    commandResults.push(
      await runVerificationCommand(
        command.name,
        command.argv,
        verifyRepo,
        command.timeout_seconds,
        workerImage,
      ),
    );
    await assertExactCandidate(task, manifest, verifyRepo);
  }
  const verificationEndedAt = new Date().toISOString();
  const verification = buildVerificationReport(plan, {
    startedAt: verificationStartedAt,
    endedAt: verificationEndedAt,
    commandResults,
    gates: {},
    verifier: {
      machine_id: machineId,
      build: "github-actions-verifier-v1",
    },
  });
  await writeFile(
    join(outputDir, "verification-report.json"),
    JSON.stringify(verification, null, 2) + "\n",
    { mode: 0o600 },
  );
}

main().catch((error) => {
  if (error instanceof ControllerError) {
    console.error(JSON.stringify({
      name: error.name,
      code: error.code,
      message: error.message,
      details: error.details ?? null,
    }, null, 2));
  } else {
    console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  }
  process.exitCode = 1;
});

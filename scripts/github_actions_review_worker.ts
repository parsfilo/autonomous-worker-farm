import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import type { RepoPassport, ResultManifest, TaskSpec } from "../contracts/types.js";
import { ContractRegistry } from "../src/contracts/schema-validator.js";
import { sha256Bytes } from "../src/evidence/candidate.js";
import {
  finalizeIndependentReviewReport,
  parseOpenCodeReviewOutput,
  sha256Text,
} from "../src/evidence/independent-review.js";
import { collectGitCandidate } from "../src/execution/claimed-attempt-executor.js";
import { parseGitHubActionsResultArtifact } from "../src/execution/github-actions-artifact.js";
import { githubActionsReviewRequestHash } from "../src/execution/github-actions-review-binding.js";
import {
  OPENCODE_REVIEW_RUN_ARGV,
  renderOpenCodeTaskDocument,
} from "../src/harness/opencode/adapter.js";
import { renderOpenCodeAttemptConfig } from "../src/harness/opencode/attempt-config.js";
import { ControllerError } from "../src/lib/errors.js";

const execFileAsync = promisify(execFile);
const contracts = new ContractRegistry();
const MAX_OUTPUT = 16 * 1024 * 1024;

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error("missing required environment variable: " + name);
  return value;
}

function decodeJson<T>(name: string): T {
  return JSON.parse(
    Buffer.from(requiredEnv(name), "base64url").toString("utf8"),
  ) as T;
}

function safeDockerImage(value: string): string {
  if (!/^[A-Za-z0-9._/@:-]{1,256}$/.test(value)) {
    throw new Error("unsafe Docker image reference");
  }
  return value;
}

async function git(args: string[], cwd: string): Promise<string> {
  try {
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
  } catch (error) {
    throw new ControllerError(
      "REVIEW_PATCH_APPLY_FAILED",
      "Trusted review preparation Git command failed",
      { cause: error instanceof Error ? error.message : String(error) },
    );
  }
}

async function docker(
  args: string[],
  timeoutMs = 120_000,
): Promise<{ stdout: Buffer; stderr: Buffer }> {
  try {
    const result = await execFileAsync("/usr/bin/docker", args, {
      timeout: timeoutMs,
      maxBuffer: MAX_OUTPUT,
      encoding: "buffer",
      env: { PATH: "/usr/bin:/bin", HOME: "/nonexistent", LANG: "C.UTF-8" },
    });
    return { stdout: Buffer.from(result.stdout), stderr: Buffer.from(result.stderr) };
  } catch (error) {
    const value = error as { code?: number | string; stdout?: Buffer | string; stderr?: Buffer | string };
    throw new ControllerError(
      "GITHUB_ACTIONS_DOCKER_FAILED",
      "Trusted GitHub Actions review Docker command failed",
      {
        argv: args.slice(0, 24),
        exit_code: value.code ?? null,
        stdout: value.stdout ? Buffer.from(value.stdout).toString("utf8").slice(-4000) : "",
        stderr: value.stderr ? Buffer.from(value.stderr).toString("utf8").slice(-4000) : "",
      },
    );
  }
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
    throw new ControllerError("BASE_DRIFT", "Review checkout is not at exact base SHA");
  }
  const remotes = (await git(["remote"], destination)).trim().split("\n").filter(Boolean);
  for (const remote of remotes) await git(["remote", "remove", remote], destination);
}

async function imageId(image: string): Promise<string> {
  const result = await docker(["image", "inspect", image, "--format", "{{.Id}}"]);
  const id = result.stdout.toString("utf8").trim().toLowerCase();
  if (!/^sha256:[0-9a-f]{64}$/.test(id)) {
    throw new Error("worker image id is not a canonical sha256 digest");
  }
  return id;
}

async function runReviewer(input: {
  reviewId: string;
  task: TaskSpec;
  passport: RepoPassport;
  repoPath: string;
  controlDir: string;
  artifactDir: string;
  workerImage: string;
  gatewayImage: string;
}): Promise<{ stdout: string; startedAt: string; endedAt: string; imageDigest: string }> {
  const suffix = input.reviewId.replace(/[^A-Za-z0-9_.-]/g, "-").slice(-64);
  const workerNetwork = "awf-review-worker-" + suffix;
  const egressNetwork = "awf-review-egress-" + suffix;
  const gatewayName = "awf-review-gateway-" + suffix;
  const workerName = "awf-review-" + suffix;
  const uid = process.getuid?.() ?? 1001;
  const gid = process.getgid?.() ?? 1001;
  const digest = await imageId(input.workerImage);

  await docker(["network", "create", "--internal", workerNetwork]);
  try {
    await docker(["network", "create", egressNetwork]);
    try {
      await docker([
        "run", "-d", "--name", gatewayName,
        "--network", egressNetwork,
        "--read-only", "--cap-drop=ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "256m", "--cpus", "1",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        input.gatewayImage,
        "--mode", "opencode-free-connect", "--listen", ":8888",
        "--proxy-host", "opencode.ai", "--proxy-port", "443",
        "--max-concurrent-requests", "8",
      ]);
      await docker(["network", "connect", "--alias", "awf-egress", workerNetwork, gatewayName]);
      const startedAt = new Date().toISOString();
      const result = await docker(
        [
          "run", "--rm", "--name", workerName,
          "--network", workerNetwork,
          "--read-only", "--cap-drop=ALL",
          "--security-opt", "no-new-privileges",
          "--pids-limit", "256", "--memory", "4g", "--cpus", "2",
          "--tmpfs", "/tmp:rw,nosuid,size=512m",
          "--user", String(uid) + ":" + String(gid),
          "--mount", "type=bind,src=" + input.repoPath + ",dst=/run/repo,readonly",
          "--mount", "type=bind,src=" + input.controlDir + ",dst=/run/control,readonly",
          "--mount", "type=bind,src=" + input.artifactDir + ",dst=/run/artifacts",
          "--env", "HOME=/tmp/home",
          "--env", "XDG_CONFIG_HOME=/tmp/.config",
          "--env", "XDG_CACHE_HOME=/tmp/.cache",
          "--env", "XDG_DATA_HOME=/tmp/.local/share",
          "--env", "TMPDIR=/tmp",
          "--env", "OPENCODE_DISABLE_PROJECT_CONFIG=1",
          "--env", "OPENCODE_CONFIG_DIR=/run/control/opencode",
          "--env", "OPENCODE_DB=:memory:",
          "--env", "AWF_REPO_DIR=/run/repo",
          "--env", "AWF_ARTIFACT_DIR=/run/artifacts",
          "--env", "AWF_REPO_ID=" + input.passport.repo_id,
          "--env", "AWF_TASK_ID=" + input.task.task_id,
          "--env", "HTTPS_PROXY=http://awf-egress:8888",
          "--env", "https_proxy=http://awf-egress:8888",
          "--env", "HTTP_PROXY=http://awf-egress:8888",
          "--env", "http_proxy=http://awf-egress:8888",
          "--env", "NO_PROXY=127.0.0.1,localhost,::1",
          "--env", "no_proxy=127.0.0.1,localhost,::1",
          "--env", "CI=true",
          "--workdir", "/run",
          input.workerImage,
          ...OPENCODE_REVIEW_RUN_ARGV,
        ],
        input.task.timeout_seconds * 1000,
      );
      return {
        stdout: result.stdout.toString("utf8"),
        startedAt,
        endedAt: new Date().toISOString(),
        imageDigest: digest,
      };
    } finally {
      try { await docker(["rm", "-f", gatewayName]); } catch {}
      try { await docker(["network", "rm", egressNetwork]); } catch {}
    }
  } finally {
    try { await docker(["network", "rm", workerNetwork]); } catch {}
  }
}

async function main(): Promise<void> {
  const task = contracts.validate<TaskSpec>("task-spec", decodeJson("AWF_TASK_B64"));
  const passport = contracts.validate<RepoPassport>("repo-passport", decodeJson("AWF_PASSPORT_B64"));
  const reviewId = requiredEnv("AWF_REVIEW_ID");
  const sourceAttemptId = requiredEnv("AWF_SOURCE_ATTEMPT_ID");
  const machineId = requiredEnv("AWF_MACHINE_ID");
  const model = requiredEnv("AWF_MODEL");
  const expectedCandidateHash = requiredEnv("AWF_CANDIDATE_HASH");
  const expectedPatchSha = requiredEnv("AWF_PATCH_SHA256");
  const workerRepo = requiredEnv("AWF_WORKER_REPO");
  const workflow = requiredEnv("AWF_WORKFLOW");
  const workflowSha = requiredEnv("AWF_WORKFLOW_SHA").toLowerCase();
  const sourceArtifactId = Number(requiredEnv("AWF_SOURCE_ARTIFACT_ID"));
  const sourceArtifactDigest = requiredEnv("AWF_SOURCE_ARTIFACT_DIGEST");
  const sourceZip = resolve(requiredEnv("AWF_SOURCE_ARTIFACT_ZIP"));
  const targetSource = resolve(requiredEnv("AWF_TARGET_CHECKOUT"));
  const outputDir = resolve(requiredEnv("AWF_OUTPUT_DIR"));
  const runnerTemp = resolve(requiredEnv("RUNNER_TEMP"));
  const workerImage = safeDockerImage(requiredEnv("AWF_WORKER_IMAGE"));
  const gatewayImage = safeDockerImage(requiredEnv("AWF_GATEWAY_IMAGE"));
  const opencodeVersion = requiredEnv("AWF_OPENCODE_VERSION");

  if (
    task.repo_id !== passport.repo_id ||
    task.archetype !== "independent-reviewer" ||
    task.write_scope.length !== 0
  ) {
    throw new Error("review task/passport/read-only binding mismatch");
  }
  const zipBytes = new Uint8Array(await (await import("node:fs/promises")).readFile(sourceZip));
  const actualArtifactDigest = "sha256:" + createHash("sha256").update(zipBytes).digest("hex");
  if (actualArtifactDigest !== sourceArtifactDigest) {
    throw new Error("source artifact digest mismatch");
  }
  const sourceArtifact = await parseGitHubActionsResultArtifact(zipBytes);
  const sourceManifest = contracts.validate<ResultManifest>(
    "result-manifest",
    JSON.parse(sourceArtifact.manifestJson),
  );
  if (
    sourceManifest.attempt_id !== sourceAttemptId ||
    sourceManifest.candidate_hash !== expectedCandidateHash ||
    sourceManifest.patch_sha256 !== expectedPatchSha ||
    sha256Bytes(sourceArtifact.patchBytes) !== expectedPatchSha ||
    sourceManifest.base_sha !== task.base_sha
  ) {
    throw new Error("source candidate artifact is not bound to requested review");
  }

  const runRoot = join(runnerTemp, "awf-review-" + reviewId);
  const repoPath = join(runRoot, "repo");
  const controlDir = join(runRoot, "control");
  const opencodeDir = join(controlDir, "opencode");
  const artifactDir = join(runRoot, "artifacts");
  await rm(runRoot, { recursive: true, force: true });
  for (const path of [controlDir, opencodeDir, artifactDir, outputDir]) {
    await mkdir(path, { recursive: true, mode: 0o700 });
  }
  await prepareBaseCopy(targetSource, repoPath, task.base_sha);
  const patchPath = join(runRoot, "candidate.patch");
  await writeFile(patchPath, sourceArtifact.patchBytes, { mode: 0o600 });
  await git(["apply", "--check", "--binary", patchPath], repoPath);
  await git(["apply", "--binary", "--whitespace=nowarn", patchPath], repoPath);
  const evidence = await collectGitCandidate(repoPath, task.base_sha);
  if (
    sha256Bytes(evidence.patchBytes) !== expectedPatchSha ||
    JSON.stringify([...evidence.changedFiles].sort()) !==
      JSON.stringify([...sourceManifest.changed_files].sort())
  ) {
    throw new Error("review workspace did not reproduce exact candidate");
  }

  const rendered = renderOpenCodeAttemptConfig(task, passport, "/run", {
    model,
    allowedShellPatterns: [],
    approvedSkillIds: [],
    readOnlyReviewMode: true,
  });
  await writeFile(join(opencodeDir, "opencode.json"), JSON.stringify(rendered.config, null, 2) + "\n", { mode: 0o600 });
  await writeFile(join(controlDir, "task.md"), renderOpenCodeTaskDocument(task), { mode: 0o600 });

  const execution = await runReviewer({
    reviewId,
    task,
    passport,
    repoPath,
    controlDir,
    artifactDir,
    workerImage,
    gatewayImage,
  });
  const parsed = parseOpenCodeReviewOutput(execution.stdout);
  const requestHash = githubActionsReviewRequestHash({
    reviewId,
    taskId: task.task_id,
    sourceAttemptId,
    candidateHash: expectedCandidateHash,
    patchSha256: expectedPatchSha,
    machineId,
    model,
    workerRepo,
    workflow,
    workflowSha,
    sourceArtifactId,
    sourceArtifactDigest,
  });
  const report = finalizeIndependentReviewReport({
    schema_version: "1.0",
    review_id: reviewId,
    task_id: task.task_id,
    source_attempt_id: sourceAttemptId,
    review_attempt_id: reviewId,
    candidate_hash: expectedCandidateHash,
    patch_sha256: expectedPatchSha,
    base_sha: task.base_sha,
    verdict: parsed.verdict,
    findings: parsed.findings,
    summary: parsed.summary,
    reviewer: {
      machine_id: machineId,
      provider: "opencode",
      model,
      harness_adapter: "opencode",
      harness_version: opencodeVersion,
    },
    sandbox: {
      tier: "T1",
      request_hash: requestHash,
      image_digest: execution.imageDigest,
      network_profile: "brokered",
      workspace_read_only: true,
    },
    started_at: execution.startedAt,
    ended_at: execution.endedAt,
    raw_output_sha256: sha256Text(execution.stdout),
  });
  await writeFile(
    join(outputDir, "independent-review-report.json"),
    JSON.stringify(report, null, 2) + "\n",
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

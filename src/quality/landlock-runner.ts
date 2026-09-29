import { execFile } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import type {
  ValidationPlan,
  VerificationCommandResult,
} from "../../contracts/types.js";
import { sha256Bytes } from "../evidence/candidate.js";
import { ControllerError } from "../lib/errors.js";

const execFileAsync = promisify(execFile);
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

export interface TrustedQualityTool {
  executable: string;
  readOnlyRoots?: string[];
}

export interface LandlockQualityRunnerOptions {
  runnerPath: string;
  validationRoot: string;
  tools: Record<string, TrustedQualityTool>;
  systemReadOnlyRoots?: string[];
}

export interface QualityCommandExecution {
  result: VerificationCommandResult;
  stdout: Uint8Array;
  stderr: Uint8Array;
}

function bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function pathInside(parent: string, child: string): boolean {
  const base = resolve(parent);
  const target = resolve(child);
  return target === base || target.startsWith(base + "/");
}

function uniqueExisting(paths: string[]): string[] {
  return [...new Set(paths.map((entry) => resolve(entry)))].filter(existsSync);
}

export class LandlockQualityCommandRunner {
  readonly #runnerPath: string;
  readonly #validationRoot: string;
  readonly #tools: Record<string, TrustedQualityTool>;
  readonly #systemReadOnlyRoots: string[];

  constructor(options: LandlockQualityRunnerOptions) {
    this.#runnerPath = realpathSync(options.runnerPath);
    this.#validationRoot = realpathSync(options.validationRoot);
    if (!lstatSync(this.#validationRoot).isDirectory()) {
      throw new ControllerError(
        "VALIDATION_ROOT_INVALID",
        "Quality validation root must be a directory",
      );
    }
    this.#tools = structuredClone(options.tools);
    this.#systemReadOnlyRoots = uniqueExisting(
      options.systemReadOnlyRoots ?? ["/usr", "/bin", "/lib", "/lib64", "/etc"],
    );

    if (!existsSync(this.#runnerPath) || !lstatSync(this.#runnerPath).isFile()) {
      throw new ControllerError(
        "QUALITY_RUNNER_INVALID",
        "Landlock quality runner binary is missing",
      );
    }
    for (const [name, tool] of Object.entries(this.#tools)) {
      if (!/^[A-Za-z0-9._+-]{1,64}$/.test(name)) {
        throw new ControllerError("QUALITY_TOOL_INVALID", "Invalid trusted quality tool name", {
          name,
        });
      }
      const executable = realpathSync(tool.executable);
      if (!lstatSync(executable).isFile()) {
        throw new ControllerError(
          "QUALITY_TOOL_INVALID",
          "Trusted quality tool must resolve to a regular file",
          { name, executable },
        );
      }
      this.#tools[name] = {
        executable,
        readOnlyRoots: uniqueExisting(tool.readOnlyRoots ?? []),
      };
    }
  }

  async run(
    plan: ValidationPlan,
    command: ValidationPlan["commands"][number],
  ): Promise<QualityCommandExecution> {
    if (plan.network_profile !== "none") {
      throw new ControllerError(
        "QUALITY_NETWORK_UNSUPPORTED",
        "Landlock local verifier currently supports network_profile=none only",
      );
    }
    const workspace = realpathSync(plan.validation_workspace);
    if (
      workspace === this.#validationRoot ||
      !pathInside(this.#validationRoot, workspace)
    ) {
      throw new ControllerError(
        "VALIDATION_WORKSPACE_INVALID",
        "Validation workspace must be a child of the trusted validation root",
      );
    }
    if (!lstatSync(workspace).isDirectory()) {
      throw new ControllerError(
        "VALIDATION_WORKSPACE_INVALID",
        "Validation workspace must be a directory",
      );
    }

    const toolName = command.argv[0]!;
    if (toolName.includes("/") || toolName.includes("\\") || !this.#tools[toolName]) {
      throw new ControllerError(
        "QUALITY_TOOL_NOT_ALLOWED",
        "Validation command executable is not in the trusted quality tool registry",
        { tool: toolName },
      );
    }
    const tool = this.#tools[toolName]!;

    const runtimeRoot = mkdtempSync(join(tmpdir(), "awf-quality-runner-"));
    const scratchRoot = mkdtempSync(join(this.#validationRoot, ".awf-quality-scratch-"));
    const toolBin = join(runtimeRoot, "bin");
    const home = join(scratchRoot, "home");
    const temp = join(scratchRoot, "tmp");
    const xdgConfig = join(home, ".config");
    const xdgCache = join(home, ".cache");
    const xdgData = join(home, ".local", "share");
    mkdirSync(toolBin, { mode: 0o700 });
    mkdirSync(home, { recursive: true, mode: 0o700 });
    mkdirSync(temp, { recursive: true, mode: 0o700 });
    mkdirSync(xdgConfig, { recursive: true, mode: 0o700 });
    mkdirSync(xdgCache, { recursive: true, mode: 0o700 });
    mkdirSync(xdgData, { recursive: true, mode: 0o700 });

    try {
      for (const [name, registered] of Object.entries(this.#tools)) {
        symlinkSync(registered.executable, join(toolBin, name));
      }
      chmodSync(toolBin, 0o555);

      const landlockArgs: string[] = [];
      for (const path of this.#systemReadOnlyRoots) {
        landlockArgs.push("--ro", path);
      }
      landlockArgs.push("--ro", toolBin);
      for (const registered of Object.values(this.#tools)) {
        landlockArgs.push("--ro", registered.executable);
        for (const path of registered.readOnlyRoots ?? []) {
          landlockArgs.push("--ro", path);
        }
      }
      if (existsSync("/dev/null")) landlockArgs.push("--rw", "/dev/null");
      if (existsSync("/dev/urandom")) landlockArgs.push("--ro", "/dev/urandom");
      landlockArgs.push("--rw", workspace);
      landlockArgs.push("--rw", scratchRoot);
      landlockArgs.push("--", tool.executable, ...command.argv.slice(1));

      const started = Date.now();
      let stdout = "";
      let stderr = "";
      let exitCode = 0;
      try {
        const result = await execFileAsync(this.#runnerPath, landlockArgs, {
          cwd: workspace,
          timeout: command.timeout_seconds * 1000,
          maxBuffer: MAX_OUTPUT_BYTES,
          env: {
            PATH: toolBin + ":/usr/bin:/bin",
            HOME: home,
            TMPDIR: temp,
            XDG_CONFIG_HOME: xdgConfig,
            XDG_CACHE_HOME: xdgCache,
            XDG_DATA_HOME: xdgData,
            LANG: "C.UTF-8",
            LC_ALL: "C.UTF-8",
            CI: "1",
            NO_COLOR: "1",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_TERMINAL_PROMPT: "0",
            SEMGREP_SEND_METRICS: "off",
            SEMGREP_ENABLE_VERSION_CHECK: "0",
          },
          encoding: "utf8",
        });
        stdout = result.stdout;
        stderr = result.stderr;
      } catch (error) {
        const value = error as {
          code?: number | string;
          killed?: boolean;
          signal?: string | null;
          stdout?: string;
          stderr?: string;
          message?: string;
        };
        stdout = value.stdout ?? "";
        stderr = value.stderr ?? "";
        if (value.killed || value.signal) {
          throw new ControllerError(
            "QUALITY_COMMAND_TIMEOUT",
            "Quality command exceeded its trusted timeout",
            { command: command.name, timeoutSeconds: command.timeout_seconds },
          );
        }
        if (typeof value.code !== "number") {
          throw new ControllerError(
            "QUALITY_RUNNER_FAILED",
            "Quality command runner failed before producing an exit code",
            { command: command.name, cause: value.message ?? String(error) },
          );
        }
        exitCode = value.code;
        if (exitCode === 125 || exitCode === 126) {
          throw new ControllerError(
            "QUALITY_RUNNER_ISOLATION_FAILED",
            "Landlock runner could not establish or execute the isolation boundary",
            { command: command.name, exitCode, stderr: stderr.slice(0, 1000) },
          );
        }
      }

      const stdoutBytes = bytes(stdout);
      const stderrBytes = bytes(stderr);
      return {
        result: {
          name: command.name,
          argv: [...command.argv],
          exit_code: exitCode,
          duration_ms: Math.max(0, Date.now() - started),
          stdout_sha256: sha256Bytes(stdoutBytes),
          stderr_sha256: sha256Bytes(stderrBytes),
        },
        stdout: stdoutBytes,
        stderr: stderrBytes,
      };
    } finally {
      if (existsSync(toolBin)) {
        try {
          chmodSync(toolBin, 0o700);
        } catch {
          // Best-effort mode restoration; rmSync below remains authoritative.
        }
      }
      rmSync(runtimeRoot, { recursive: true, force: true });
      rmSync(scratchRoot, { recursive: true, force: true });
    }
  }
}

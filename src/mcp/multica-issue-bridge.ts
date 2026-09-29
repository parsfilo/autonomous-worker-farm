import { execFile } from "node:child_process";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

const execFileAsync = promisify(execFile);
const ISSUE_ID = /^[0-9a-f]{8}-[0-9a-f-]{27}$/i;
const ALLOWED_STATUSES = new Set(["todo", "in_progress", "in_review", "blocked"]);

function result(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
    structuredContent: value as Record<string, unknown>,
  };
}

export function currentIssueId(cwd = process.cwd()): string {
  const root = realpathSync(cwd);
  const contextPath = resolve(root, ".multica", "daemon_task_context.json");
  const info = lstatSync(contextPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error("Multica task context must be a regular non-symlink file");
  }
  const resolved = realpathSync(contextPath);
  const rel = relative(root, resolved);
  if (!rel || rel.startsWith("..") || rel.startsWith("/")) {
    throw new Error("Multica task context escaped the current run workdir");
  }
  const parsed = JSON.parse(readFileSync(resolved, "utf8")) as {
    managed_by?: unknown;
    issue_id?: unknown;
  };
  if (
    parsed.managed_by !== "multica-daemon-task" ||
    typeof parsed.issue_id !== "string" ||
    !ISSUE_ID.test(parsed.issue_id)
  ) {
    throw new Error("Multica task context is missing a valid current issue id");
  }
  return parsed.issue_id;
}

export interface MulticaCommandRunner {
  run(args: string[]): Promise<unknown>;
}

export class ExecMulticaCommandRunner implements MulticaCommandRunner {
  readonly #binary: string;
  readonly #workspaceId: string;
  readonly #cwd: string;
  readonly #taskToken: string;
  readonly #serverUrl: string;

  constructor(input: { workspaceId: string; cwd?: string; binary?: string; taskToken?: string; serverUrl?: string }) {
    if (!ISSUE_ID.test(input.workspaceId)) {
      throw new Error("AWF Multica workspace id must be a UUID");
    }
    this.#workspaceId = input.workspaceId;
    this.#cwd = input.cwd ?? process.cwd();
    this.#binary = input.binary ?? "/usr/local/bin/multica";
    const taskToken = input.taskToken ?? process.env.MULTICA_TOKEN ?? "";
    if (!taskToken.startsWith("mat_") || taskToken.length <= 4) {
      throw new Error("AWF Multica issue bridge requires a task-scoped mat_ token");
    }
    this.#taskToken = taskToken;
    const serverUrl = input.serverUrl ?? process.env.AWF_MULTICA_SERVER_URL ?? "https://api.multica.ai";
    if (serverUrl !== "https://api.multica.ai") {
      throw new Error("AWF Multica issue bridge server URL must be the canonical Multica API origin");
    }
    this.#serverUrl = serverUrl;
  }

  async run(args: string[]): Promise<unknown> {
    const { stdout } = await execFileAsync(
      this.#binary,
      [...args, "--workspace-id", this.#workspaceId, "--output", "json"],
      {
        cwd: this.#cwd,
        timeout: 30_000,
        maxBuffer: 4 * 1024 * 1024,
        env: {
          HOME: process.env.HOME ?? "/home/ubuntu",
          PATH: "/usr/local/bin:/usr/bin:/bin",
          LANG: "C.UTF-8",
          MULTICA_TOKEN: this.#taskToken,
          MULTICA_SERVER_URL: this.#serverUrl,
        },
      },
    );
    return JSON.parse(stdout);
  }
}

export class CurrentIssueBridge {
  readonly #cwd: string;
  readonly #runner: MulticaCommandRunner;

  constructor(input: { runner: MulticaCommandRunner; cwd?: string }) {
    this.#runner = input.runner;
    this.#cwd = input.cwd ?? process.cwd();
  }

  async getContext(): Promise<Record<string, unknown>> {
    const issueId = currentIssueId(this.#cwd);
    const [issue, comments] = await Promise.all([
      this.#runner.run(["issue", "get", issueId]),
      this.#runner.run([
        "issue",
        "comment",
        "list",
        issueId,
        "--roots-only",
        "--summary",
        "--compact",
      ]),
    ]);
    return { issue_id: issueId, issue, comments };
  }

  async comment(content: string, parentCommentId?: string): Promise<Record<string, unknown>> {
    const issueId = currentIssueId(this.#cwd);
    const trimmed = content.trim();
    if (!trimmed || trimmed.length > 16_000) {
      throw new Error("Issue comment must contain 1-16000 non-whitespace characters");
    }
    const tempRoot = mkdtempSync(join(this.#cwd, ".multica", "awf-issue-bridge-"));
    const bodyPath = join(tempRoot, "comment.md");
    try {
      writeFileSync(bodyPath, trimmed + "\n", { encoding: "utf8", mode: 0o600 });
      const args = ["issue", "comment", "add", issueId, "--content-file", bodyPath];
      if (parentCommentId) {
        if (!ISSUE_ID.test(parentCommentId)) {
          throw new Error("Parent comment id must be a UUID");
        }
        args.push("--parent", parentCommentId);
      }
      const response = await this.#runner.run(args);
      return { issue_id: issueId, response };
    } finally {
      rmSync(tempRoot, { recursive: true, force: true });
    }
  }

  async setStatus(status: string): Promise<Record<string, unknown>> {
    if (!ALLOWED_STATUSES.has(status)) {
      throw new Error("Frontier issue bridge status is not allowed");
    }
    const issueId = currentIssueId(this.#cwd);
    const response = await this.#runner.run(["issue", "status", issueId, status]);
    return { issue_id: issueId, status, response };
  }
}

export function buildMulticaIssueBridge(service: CurrentIssueBridge): McpServer {
  const server = new McpServer({ name: "awf-multica-issue-bridge", version: "0.1.0" });

  server.registerTool(
    "issue.get_current_context",
    {
      description:
        "Read only the Multica issue assigned to the current daemon run plus bounded root-comment summaries.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => result(await service.getContext()),
  );

  server.registerTool(
    "issue.comment_current",
    {
      description:
        "Post the current run's final/status comment to its own Multica issue. Cannot target another issue.",
      inputSchema: z.object({
        content: z.string().min(1).max(16_000),
        parent_comment_id: z.string().optional(),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ content, parent_comment_id }) =>
      result(await service.comment(content, parent_comment_id)),
  );

  server.registerTool(
    "issue.set_current_status",
    {
      description:
        "Set the current Multica issue to todo, in_progress, in_review, or blocked. DONE remains human-owned.",
      inputSchema: z.object({
        status: z.enum(["todo", "in_progress", "in_review", "blocked"]),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ status }) => result(await service.setStatus(status)),
  );

  return server;
}

export async function runMulticaIssueBridge(): Promise<void> {
  const workspaceId = process.env.AWF_MULTICA_WORKSPACE_ID?.trim();
  if (!workspaceId) {
    throw new Error("AWF_MULTICA_WORKSPACE_ID is required");
  }
  const cwd = process.cwd();
  const runner = new ExecMulticaCommandRunner({ workspaceId, cwd });
  const service = new CurrentIssueBridge({ runner, cwd });
  // Fail before exposing tools when this is not a daemon-managed issue workdir.
  currentIssueId(cwd);
  await serveStdio(() => buildMulticaIssueBridge(service));
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  void runMulticaIssueBridge();
}

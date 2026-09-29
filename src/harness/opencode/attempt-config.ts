import type { RepoPassport, TaskSpec } from "../../../contracts/types.js";
import { ControllerError } from "../../lib/errors.js";

export interface PermissionRule {
  action: string;
  resource: string;
  effect: "allow" | "deny" | "ask";
}

export interface ResolvedAttemptPolicy {
  model?: string;
  openCodeProvider?: {
    model: string;
    providers: Record<string, unknown>;
  };
  proxyURL?: string;
  allowedShellPatterns: string[];
  approvedSkillIds: string[];
  allowedMcpActions?: string[];
  readOnlyReviewMode?: boolean;
}

export interface OpenCodeAttemptConfig {
  config: Record<string, unknown>;
  env: Record<string, string>;
  workingDirectory: string;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function isOpenCodeFreeModel(model: string | undefined): boolean {
  if (!model?.startsWith("opencode/")) return false;
  const id = model.slice("opencode/".length);
  return id === "big-pickle" || id.endsWith("-free");
}

function proxyEnvironment(proxyURL: string | undefined): Record<string, string> {
  if (!proxyURL) return {};
  let parsed: URL;
  try {
    parsed = new URL(proxyURL);
  } catch {
    throw new ControllerError("INVALID_EGRESS_PROXY", "Egress proxy URL is invalid");
  }
  const port = Number(parsed.port);
  if (
    parsed.protocol !== "http:" ||
    parsed.hostname !== "awf-egress" ||
    !Number.isInteger(port) ||
    port < 1024 ||
    port > 65535 ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash
  ) {
    throw new ControllerError(
      "INVALID_EGRESS_PROXY",
      "Only the broker-managed http://awf-egress:<port> proxy is allowed",
    );
  }
  return {
    HTTPS_PROXY: proxyURL,
    https_proxy: proxyURL,
    HTTP_PROXY: proxyURL,
    http_proxy: proxyURL,
    NO_PROXY: "127.0.0.1,localhost,::1",
    no_proxy: "127.0.0.1,localhost,::1",
  };
}

function normalizeRepoScope(resource: string): string {
  const normalized = resource.replaceAll("\\", "/").replace(/^\.\//, "");
  if (
    !normalized ||
    normalized.startsWith("/") ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    normalized.includes("/../")
  ) {
    throw new ControllerError("INVALID_REPO_SCOPE", "Task scope is not a safe repository-relative pattern", {
      resource,
    });
  }
  return normalized;
}

function repoPatterns(resource: string): string[] {
  const normalized = normalizeRepoScope(resource);
  // OpenCode evaluates tool resources relative to the current session
  // directory. A session may remain at /run or move into /run/repo.
  return unique(["repo/" + normalized, normalized]);
}

export function renderOpenCodeAttemptConfig(
  task: TaskSpec,
  passport: RepoPassport,
  containerRunRoot = "/run",
  resolved: ResolvedAttemptPolicy,
): OpenCodeAttemptConfig {
  if (resolved.readOnlyReviewMode) {
    if (task.archetype !== "independent-reviewer" || task.write_scope.length !== 0) {
      throw new ControllerError(
        "INVALID_REVIEW_SANDBOX_POLICY",
        "readOnlyReviewMode requires independent-reviewer with empty write_scope",
      );
    }
    const reviewModel = resolved.openCodeProvider?.model ?? resolved.model;
    if (!reviewModel) {
      throw new ControllerError(
        "REVIEW_MODEL_REQUIRED",
        "Read-only OpenCode review requires an exact Controller-selected model binding",
      );
    }
    const config: Record<string, unknown> = {
      $schema: "https://opencode.ai/config.json",
      update: "disable",
      model: reviewModel,
      agent: {
        plan: {
          mode: "primary",
          model: reviewModel,
          permission: {
            edit: "deny",
            bash: {
              "*": "deny",
              pwd: "allow",
            },
            webfetch: "deny",
          },
        },
      },
    };
    if (resolved.openCodeProvider) {
      config.providers = resolved.openCodeProvider.providers;
    }
    return {
      config,
      workingDirectory: containerRunRoot,
      env: {
        HOME: "/home/worker",
        XDG_CONFIG_HOME: "/tmp/.config",
        XDG_CACHE_HOME: "/tmp/.cache",
        XDG_DATA_HOME: "/tmp/.local/share",
        TMPDIR: "/tmp",
        OPENCODE_DISABLE_PROJECT_CONFIG: "1",
        OPENCODE_CONFIG_DIR: containerRunRoot + "/control/opencode",
        OPENCODE_DB: ":memory:",
        AWF_REPO_DIR: containerRunRoot + "/repo",
        AWF_ARTIFACT_DIR: containerRunRoot + "/artifacts",
        AWF_REPO_ID: passport.repo_id,
        AWF_TASK_ID: task.task_id,
        ...proxyEnvironment(resolved.proxyURL),
      },
    };
  }

  const shellPatterns = unique(resolved.allowedShellPatterns);
  // OpenCode Console free-tier rejects a fresh noninteractive session when the
  // shell tool is globally denied with no allowed command at all. Keep the
  // deny-by-default boundary and expose only an exact, non-mutating fallback.
  if (isOpenCodeFreeModel(resolved.model) && shellPatterns.length === 0) {
    shellPatterns.push("pwd");
  }

  const permissions: PermissionRule[] = [
    { action: "external_directory", resource: "*", effect: "deny" },

    // Run-root is trusted Controller material; model read tools are repo-scoped.
    { action: "read", resource: "*", effect: "deny" },
    ...task.read_scope.flatMap((resource) =>
      repoPatterns(resource).map((pattern) => ({
        action: "read",
        resource: pattern,
        effect: "allow" as const,
      })),
    ),
    ...task.denied_paths.flatMap((resource) =>
      repoPatterns(resource).map((pattern) => ({
        action: "read",
        resource: pattern,
        effect: "deny" as const,
      })),
    ),
    { action: "read", resource: "control/**", effect: "deny" },
    { action: "read", resource: "control/task.md", effect: "allow" },
    { action: "read", resource: "artifacts/**", effect: "deny" },
    { action: "read", resource: "egress/**", effect: "deny" },

    // Edits are denied globally, then narrowly enabled inside repo/.
    { action: "edit", resource: "*", effect: "deny" },
    ...task.write_scope.flatMap((resource) =>
      repoPatterns(resource).map((pattern) => ({
        action: "edit",
        resource: pattern,
        effect: "allow" as const,
      })),
    ),
    ...task.denied_paths.flatMap((resource) =>
      repoPatterns(resource).map((pattern) => ({
        action: "edit",
        resource: pattern,
        effect: "deny" as const,
      })),
    ),
    ...task.protected_paths.flatMap((resource) =>
      repoPatterns(resource).map((pattern) => ({
        action: "edit",
        resource: pattern,
        effect: "deny" as const,
      })),
    ),
    { action: "edit", resource: "control/**", effect: "deny" },
    { action: "edit", resource: "artifacts/**", effect: "deny" },
    { action: "edit", resource: "egress/**", effect: "deny" },

    // No shell command executes unless Controller resolved it into the attempt policy.
    { action: "shell", resource: "*", effect: "deny" },
    ...shellPatterns.map((resource) => ({
      action: "shell",
      resource,
      effect: "allow" as const,
    })),

    { action: "skill", resource: "*", effect: "deny" },
    ...unique(resolved.approvedSkillIds).map((resource) => ({
      action: "skill",
      resource,
      effect: "allow" as const,
    })),

    { action: "subagent", resource: "*", effect: "deny" },
  ];

  for (const action of resolved.allowedMcpActions ?? []) {
    permissions.push({ action, resource: "*", effect: "allow" });
  }

  const policies: Array<{ action: "permission"; resource: string; effect: "deny" }> = [
    { action: "permission", resource: "shell:git push *", effect: "deny" },
    { action: "permission", resource: "shell:git remote set-url *", effect: "deny" },
    { action: "permission", resource: "shell:sudo *", effect: "deny" },
    { action: "permission", resource: "shell:su *", effect: "deny" },
    { action: "permission", resource: "shell:mount *", effect: "deny" },
    { action: "permission", resource: "shell:umount *", effect: "deny" },
    { action: "permission", resource: "external_directory:*", effect: "deny" },
    { action: "permission", resource: "read:*.env", effect: "deny" },
    { action: "permission", resource: "read:*.env.*", effect: "deny" },
    { action: "permission", resource: "read:*/.ssh/*", effect: "deny" },
    { action: "permission", resource: "read:*/.aws/*", effect: "deny" },
    { action: "permission", resource: "edit:control/*", effect: "deny" },
    { action: "permission", resource: "edit:artifacts/*", effect: "deny" },
    { action: "permission", resource: "read:egress/*", effect: "deny" },
    { action: "permission", resource: "edit:egress/*", effect: "deny" },
  ];

  const config: Record<string, unknown> = {
    $schema: "https://opencode.ai/config.json",
    update: "disable",
    snapshots: false,
    permissions,
    experimental: {
      portable_shell_scanner: true,
      policies,
    },
    skills: [],
  };

  if (resolved.openCodeProvider) {
    config.model = resolved.openCodeProvider.model;
    config.providers = resolved.openCodeProvider.providers;
  } else if (resolved.model) {
    config.model = resolved.model;
  }

  return {
    config,
    workingDirectory: containerRunRoot,
    env: {
      HOME: "/home/worker",
      XDG_CONFIG_HOME: "/tmp/.config",
      XDG_CACHE_HOME: "/tmp/.cache",
      XDG_DATA_HOME: "/tmp/.local/share",
      TMPDIR: "/tmp",
      OPENCODE_DISABLE_PROJECT_CONFIG: "1",
      OPENCODE_CONFIG_DIR: containerRunRoot + "/control/opencode",
      OPENCODE_DB: ":memory:",
      AWF_REPO_DIR: containerRunRoot + "/repo",
      AWF_ARTIFACT_DIR: containerRunRoot + "/artifacts",
      AWF_REPO_ID: passport.repo_id,
      AWF_TASK_ID: task.task_id,
      ...proxyEnvironment(resolved.proxyURL),
    },
  };
}

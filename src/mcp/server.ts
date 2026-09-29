import { lstatSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import { ControllerCore } from "../controller/controller.js";
import { ClaimedAttemptExecutor } from "../execution/claimed-attempt-executor.js";
import { GitHubActionsAttemptExecutor } from "../execution/github-actions-attempt-executor.js";
import { loadExecutionBackendConfig } from "../execution/backend-config.js";
import { IndependentReviewExecutor } from "../execution/independent-review-executor.js";
import { GitHubActionsReviewExecutor } from "../execution/github-actions-review-executor.js";
import { prepareGitIntegrationArtifact } from "../repo/git-integration.js";
import {
  FileGitHubAppJwtSigner,
  GitHubAppInstallationTokenProvider,
} from "../repo/github-app-credentials.js";
import { GitHubPrExecutor } from "../repo/github-pr-executor.js";
import { GitHubRemoteObserver } from "../repo/github-remote-observer.js";
import { GitHubMergeExecutor } from "../repo/github-merge-executor.js";
import { GitHubPostMergeObserver } from "../repo/github-post-merge-observer.js";
import { LocalVerificationExecutor } from "../quality/executor.js";
import { LandlockQualityCommandRunner } from "../quality/landlock-runner.js";
import { ControllerError } from "../lib/errors.js";
import { findProjectRoot } from "../lib/project-root.js";
import { githubActionsMachineCapability } from "../machine/github-actions.js";

function result(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value) }],
    structuredContent: value as Record<string, unknown>,
  };
}

function errorResult(error: unknown) {
  const payload =
    error instanceof ControllerError
      ? { error: { code: error.code, message: error.message, details: error.details ?? null } }
      : { error: { code: "INTERNAL_ERROR", message: error instanceof Error ? error.message : String(error) } };

  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload) }],
    structuredContent: payload,
    isError: true,
  };
}

function githubCredentialsFromEnvironment(): GitHubAppInstallationTokenProvider {
  const clientId = process.env.AWF_GITHUB_APP_CLIENT_ID?.trim();
  const privateKeyPath = process.env.AWF_GITHUB_APP_PRIVATE_KEY_PATH?.trim();
  if (!clientId || !privateKeyPath) {
    throw new ControllerError(
      "PR_WRITE_CREDENTIALS_REQUIRED",
      "Trusted GitHub App credentials are not configured for PR/remote operations",
      {
        required_environment: [
          "AWF_GITHUB_APP_CLIENT_ID",
          "AWF_GITHUB_APP_PRIVATE_KEY_PATH",
        ],
      },
    );
  }
  return new GitHubAppInstallationTokenProvider({
    signer: new FileGitHubAppJwtSigner({
      clientId,
      privateKeyPath,
    }),
  });
}

function targetGitIdentityFromEnvironment(repoId: string): { name: string; email: string } {
  const name = process.env.AWF_TARGET_GIT_NAME?.trim();
  const email = process.env.AWF_TARGET_GIT_EMAIL?.trim();
  if (!name || !email) {
    throw new ControllerError(
      "GIT_INTEGRATION_IDENTITY_REQUIRED",
      "Trusted target Git author/committer identity is not configured",
      { required_environment: ["AWF_TARGET_GIT_NAME", "AWF_TARGET_GIT_EMAIL"], repoId },
    );
  }
  const owner = repoId.split("/", 1)[0] ?? "";
  const lowerEmail = email.toLowerCase();
  const ownerLower = owner.toLowerCase();
  if (
    name.toLowerCase() !== ownerLower ||
    !(
      lowerEmail === ownerLower + "@users.noreply.github.com" ||
      (/^[0-9]+\+/.test(lowerEmail) &&
        lowerEmail.endsWith("+" + ownerLower + "@users.noreply.github.com"))
    )
  ) {
    throw new ControllerError(
      "GIT_INTEGRATION_IDENTITY_MISMATCH",
      "Configured target Git identity does not belong to repository owner",
      { repoId, owner, name, email },
    );
  }
  return { name, email };
}

function githubActionsCredentialsFromEnvironment(): GitHubAppInstallationTokenProvider {
  const clientId = process.env.AWF_WORKER_GITHUB_APP_CLIENT_ID?.trim();
  const privateKeyPath =
    process.env.AWF_WORKER_GITHUB_APP_PRIVATE_KEY_PATH?.trim();
  if (!clientId || !privateKeyPath) {
    throw new ControllerError(
      "GITHUB_ACTIONS_CREDENTIALS_REQUIRED",
      "Trusted worker-farm GitHub App credentials are not configured",
      {
        required_environment: [
          "AWF_WORKER_GITHUB_APP_CLIENT_ID",
          "AWF_WORKER_GITHUB_APP_PRIVATE_KEY_PATH",
        ],
      },
    );
  }
  return new GitHubAppInstallationTokenProvider({
    signer: new FileGitHubAppJwtSigner({ clientId, privateKeyPath }),
    permissions: {
      contents: "read",
      actions: "write",
    },
  });
}

export function buildServer(core: ControllerCore): McpServer {
  const server = new McpServer({ name: "autonomous-worker-controller", version: "0.1.0" });

  server.registerTool(
    "fleet.get_state",
    {
      description: "Read authoritative Controller execution state. No secrets are returned.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => result(core.getState()),
  );

  server.registerTool(
    "fleet.list_capabilities",
    {
      description: "List registered worker-machine capabilities and canonical worker archetypes.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => result(core.listCapabilities()),
  );

  server.registerTool(
    "fleet.get_task",
    {
      description: "Read one canonical task and its immutable transition history.",
      inputSchema: z.object({ task_id: z.string().min(1).max(128) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ task_id }) => {
      try {
        return result(core.getTask(task_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "repo.register_passport",
    {
      description:
        "Validate and register a Controller-owned Repo Passport. This changes only local Controller state.",
      inputSchema: z.object({
        passport: z.record(z.string(), z.unknown()),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ passport }) => {
      try {
        return result(core.registerPassport(passport));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "repo.register_github_public_source",
    {
      description:
        "Register the canonical public GitHub source for an already-registered public Repo Passport. The repo_id must be owner/repo.",
      inputSchema: z.object({
        repo_id: z.string().min(3).max(256),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ repo_id }) => {
      try {
        return result(core.registerGitHubPublicSource(repo_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "repo.get_passport",
    {
      description: "Read the Controller-owned effective Repo Passport and its canonical SHA-256.",
      inputSchema: z.object({ repo_id: z.string().min(1).max(256) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ repo_id }) => {
      try {
        return result(core.getPassport(repo_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "machine.get_eligibility",
    {
      description: "Evaluate all registered machines against an existing task without scheduling it.",
      inputSchema: z.object({ task_id: z.string().min(1).max(128) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ task_id }) => {
      try {
        return result(core.evaluateEligibility(task_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.spawn",
    {
      description:
        "Validate and register a TaskSpec. This records a READY task but Phase 1 does not yet launch a worker process.",
      inputSchema: z.object({
        task_spec: z.record(z.string(), z.unknown()),
        idempotency_key: z.string().min(1).max(128),
        expected_revision: z.number().int().min(0).optional(),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ task_spec, idempotency_key, expected_revision }) => {
      try {
        return result(core.spawn(task_spec, idempotency_key, expected_revision));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.execute_claimed",
    {
      description:
        "Execute one already-claimed LEASED write attempt through its Controller-selected execution backend. Production github-actions attempts dispatch to the pinned public worker-farm workflow, verify GitHub-hosted OIDC/run/artifact evidence, and require deterministic verification before CANDIDATE. local-broker remains an explicit diagnostic backend.",
      inputSchema: z.object({
        attempt_id: z.string().min(1).max(128),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ attempt_id }) => {
      try {
        const projectRoot = findProjectRoot();
        const attempt = core.getAttempt(attempt_id);
        if (attempt.execution_backend === "github-actions") {
          const backend = loadExecutionBackendConfig();
          if (backend.backend !== "github-actions") {
            throw new ControllerError(
              "EXECUTION_BACKEND_MISMATCH",
              "Attempt was claimed for github-actions but Controller runtime is not configured for that backend",
            );
          }
          if (attempt.machine_id !== backend.machineId) {
            throw new ControllerError(
              "EXECUTION_BACKEND_MISMATCH",
              "Attempt logical machine does not match configured GitHub Actions machine",
              { attemptMachine: attempt.machine_id, configuredMachine: backend.machineId },
            );
          }
          const executor = new GitHubActionsAttemptExecutor({
            core,
            credentials: githubActionsCredentialsFromEnvironment(),
            workerRepo: backend.workerRepo,
            workflow: backend.workflow,
            dispatchRef: backend.dispatchRef,
            workflowSha: backend.workflowSha,
            candidateArtifactRoot: join(projectRoot, ".state", "candidates"),
            qualityProfileRoot: join(projectRoot, "profiles", "quality"),
          });
          return result(await executor.execute(attempt_id));
        }
        if (attempt.execution_backend !== undefined && attempt.execution_backend !== "local-broker") {
          throw new ControllerError(
            "EXECUTION_BACKEND_INVALID",
            "Attempt carries an unsupported execution backend",
            { executionBackend: attempt.execution_backend },
          );
        }

        const qualityProfileRoot = join(projectRoot, "profiles", "quality");
        const validationRoot = join(projectRoot, ".state", "validation");
        mkdirSync(validationRoot, { recursive: true, mode: 0o700 });
        const executor = new ClaimedAttemptExecutor({
          core,
          egressProfilePath: join(
            projectRoot,
            "deploy",
            "egress-profiles",
            "opencode-free.json",
          ),
          runtimeImageLockPath: join(
            projectRoot,
            "containers",
            "runtime-images.lock.json",
          ),
          candidateArtifactRoot: join(projectRoot, ".state", "candidates"),
          qualityProfileRoot,
          validationRoot,
        });
        const execution = await executor.execute(attempt_id);
        if (execution.attempt.state !== "LOCAL_VERIFY") {
          throw new ControllerError(
            "LOCAL_VERIFICATION_BYPASSED",
            "Controller execution must enter LOCAL_VERIFY before candidate promotion",
          );
        }
        const runner = new LandlockQualityCommandRunner({
          runnerPath: join(projectRoot, "native", "bin", "master-landlock-run"),
          validationRoot,
          tools: {
            node: {
              executable: process.execPath,
              readOnlyRoots: [dirname(dirname(process.execPath))],
            },
          },
        });
        const verifier = new LocalVerificationExecutor({
          core,
          qualityProfileRoot,
          validationRoot,
          verifierBuild: "landlock-local-v1",
          runner,
        });
        const verification = await verifier.execute(attempt_id);
        return result({
          ...execution,
          attempt: verification.attempt,
          verification_report: verification.report,
        });
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.get_attempt",
    {
      description: "Read one persisted attempt reservation and its exact machine/harness/model binding.",
      inputSchema: z.object({ attempt_id: z.string().min(1).max(128) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ attempt_id }) => {
      try {
        return result(core.getAttempt(attempt_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.claim",
    {
      description:
        "Atomically claim a READY public task onto the benchmark-qualified OpenCode free route. Reserves one machine slot and persists the exact model/harness binding; it does not launch the worker yet.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
        idempotency_key: z.string().min(1).max(128),
        correlation_id: z.string().min(1).max(128),
        actor_id: z.string().min(1).max(128),
        expected_revision: z.number().int().min(0).optional(),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({
      task_id,
      idempotency_key,
      correlation_id,
      actor_id,
      expected_revision,
    }) => {
      try {
        return result(
          core.claim(
            task_id,
            idempotency_key,
            correlation_id,
            actor_id,
            expected_revision,
          ),
        );
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.retry",
    {
      description: "Request a retry by transitioning a retryable failed task back to READY.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
        candidate_hash: z.string().regex(/^[0-9a-f]{64}$/),
        correlation_id: z.string().min(1).max(128),
        actor_id: z.string().min(1).max(128),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ task_id, correlation_id, actor_id }) => {
      try {
        return result(core.retry(task_id, correlation_id, actor_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.cancel",
    {
      description: "Request deterministic task cancellation.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
        correlation_id: z.string().min(1).max(128),
        actor_id: z.string().min(1).max(128),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    },
    async ({ task_id, correlation_id, actor_id }) => {
      try {
        return result(core.cancel(task_id, correlation_id, actor_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.request_review",
    {
      description: "Request independent review for an exact candidate hash.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
        candidate_hash: z.string().regex(/^[0-9a-f]{64}$/),
        correlation_id: z.string().min(1).max(128),
        actor_id: z.string().min(1).max(128),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
    },
    async ({ task_id, candidate_hash, correlation_id, actor_id }) => {
      try {
        return result(core.requestReview(task_id, candidate_hash, correlation_id, actor_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.get_review",
    {
      description: "Read one persisted independent-review run and its exact candidate/model binding.",
      inputSchema: z.object({ review_id: z.string().min(1).max(128) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ review_id }) => {
      try {
        return result(core.getReview(review_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.claim_review",
    {
      description:
        "Atomically claim one READY independent review onto a healthy model-diverse OpenCode free route and reserve its machine/model slot.",
      inputSchema: z.object({
        review_id: z.string().min(1).max(128),
        correlation_id: z.string().min(1).max(128),
        actor_id: z.string().min(1).max(128),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: false,
      },
    },
    async ({ review_id, correlation_id, actor_id }) => {
      try {
        return result(core.claimReview(review_id, correlation_id, actor_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "fleet.execute_review",
    {
      description:
        "Execute one already-claimed LEASED independent review through its persisted execution backend. Production github-actions reviews run model-diverse in the pinned worker-farm workflow with exact source-artifact digest binding and read-only Docker workspace; local-broker remains diagnostic only.",
      inputSchema: z.object({ review_id: z.string().min(1).max(128) }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ review_id }) => {
      try {
        const projectRoot = findProjectRoot();
        const review = core.getReview(review_id);
        if (review.execution_backend === "github-actions") {
          const backend = loadExecutionBackendConfig();
          if (backend.backend !== "github-actions") {
            throw new ControllerError(
              "EXECUTION_BACKEND_MISMATCH",
              "Review was claimed for github-actions but Controller runtime is not configured for that backend",
            );
          }
          if (review.machine_id !== backend.machineId) {
            throw new ControllerError(
              "EXECUTION_BACKEND_MISMATCH",
              "Review logical machine does not match configured GitHub Actions machine",
              { reviewMachine: review.machine_id, configuredMachine: backend.machineId },
            );
          }
          const executor = new GitHubActionsReviewExecutor({
            core,
            credentials: githubActionsCredentialsFromEnvironment(),
            workerRepo: backend.workerRepo,
            workflow: backend.workflow,
            dispatchRef: backend.dispatchRef,
            workflowSha: backend.workflowSha,
            qualityProfileRoot: join(projectRoot, "profiles", "quality"),
          });
          return result(await executor.execute(review_id));
        }
        if (review.execution_backend !== undefined && review.execution_backend !== "local-broker") {
          throw new ControllerError(
            "EXECUTION_BACKEND_INVALID",
            "Review carries an unsupported execution backend",
            { executionBackend: review.execution_backend },
          );
        }
        const executor = new IndependentReviewExecutor({
          core,
          egressProfilePath: join(
            projectRoot,
            "deploy",
            "egress-profiles",
            "opencode-free.json",
          ),
          runtimeImageLockPath: join(
            projectRoot,
            "containers",
            "runtime-images.lock.json",
          ),
        });
        return result(await executor.execute(review_id));
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "repo.prepare_integration",
    {
      description:
        "Prepare and persist the deterministic trusted Git integration commit for an independently reviewed candidate. This fetches the public base read-only and performs no push, branch, PR, or merge mutation.",
      inputSchema: z.object({
        attempt_id: z.string().min(1).max(128),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async ({ attempt_id }) => {
      const projectRoot = findProjectRoot();
      const integrationRoot = join(projectRoot, ".state", "integration-work");
      mkdirSync(integrationRoot, { recursive: true, mode: 0o700 });
      const rootInfo = lstatSync(integrationRoot);
      if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
        return errorResult(
          new ControllerError(
            "GIT_INTEGRATION_ROOT_INVALID",
            "Trusted Git integration workspace root must be a real directory",
          ),
        );
      }
      const destination = mkdtempSync(join(integrationRoot, "work-"));
      try {
        const attempt = core.getAttempt(attempt_id);
        const task = core.getTask(attempt.task_id).spec;
        const source = core.getRepoSource(task.repo_id);
        const artifact = await prepareGitIntegrationArtifact({
          source,
          task,
          attempt,
          destination,
          identity: targetGitIdentityFromEnvironment(task.repo_id),
        });
        const recorded = core.recordGitIntegrationArtifact(attempt_id, artifact);
        return result({ attempt: recorded, integration: artifact });
      } catch (error) {
        return errorResult(error);
      } finally {
        rmSync(destination, { recursive: true, force: true });
      }
    },
  );

  server.registerTool(
    "repo.request_pr",
    {
      description:
        "Publish the exact deterministic reviewed integration commit to a Controller-owned GitHub branch and create/reuse one exact-SHA pull request. Requires trusted GitHub App credentials configured on the Controller host; credentials are never returned.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
        correlation_id: z.string().min(1).max(128),
        actor_id: z.string().min(1).max(128),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ task_id, correlation_id, actor_id }) => {
      try {
        core.requestPr(task_id, correlation_id, actor_id);
        const attempt = core.getPrIntegrationCandidate(task_id);
        const credentials = githubCredentialsFromEnvironment();
        const projectRoot = findProjectRoot();
        const executor = new GitHubPrExecutor({
          core,
          credentials,
          integrationRoot: join(projectRoot, ".state", "integration-work"),
        });
        return result(
          await executor.execute({
            attemptId: attempt.attempt_id,
            correlationId: correlation_id,
            actorId: actor_id,
          }),
        );
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "repo.verify_remote",
    {
      description:
        "Re-observe the persisted GitHub pull request, base branch, exact PR head SHA, check runs and commit statuses using Controller-owned GitHub App credentials. No observed SHA/check result is accepted from the caller.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ task_id }) => {
      try {
        const taskRecord = core.getTask(task_id);
        if (taskRecord.state !== "REMOTE_VERIFY") {
          throw new ControllerError(
            "REMOTE_VERIFICATION_NOT_READY",
            "Remote verification requires task state REMOTE_VERIFY",
            { state: taskRecord.state },
          );
        }
        const attempt = core.getPrIntegrationCandidate(task_id);
        if (!attempt.integration_candidate || !attempt.pull_request) {
          throw new ControllerError(
            "REMOTE_VERIFICATION_INTEGRATION_MISSING",
            "Remote verification requires deterministic integration and persisted PR publication",
          );
        }
        const credentials = githubCredentialsFromEnvironment();
        const observer = new GitHubRemoteObserver({ credentials });
        const report = await observer.observe({
          task: taskRecord.spec,
          artifact: attempt.integration_candidate,
          publication: attempt.pull_request,
        });
        if (report.status === "PENDING") {
          return result({
            task: core.getTask(task_id),
            report,
            persisted: false,
          });
        }
        const completed = core.completeRemoteVerification(report);
        return result({ task: completed, report, persisted: true });
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "repo.request_merge",
    {
      description:
        "Perform a trusted exact-SHA GitHub merge only after READY_TO_MERGE. The Controller re-observes base/PR/check evidence immediately before merge, sends the verified PR head SHA to GitHub's merge endpoint, persists a hash-bound merge receipt, and advances to POST_MERGE_VERIFY. Requires Controller-owned GitHub App credentials.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
        correlation_id: z.string().min(1).max(128),
        actor_id: z.string().min(1).max(128),
      }),
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    async ({ task_id, correlation_id, actor_id }) => {
      try {
        const credentials = githubCredentialsFromEnvironment();
        const executor = new GitHubMergeExecutor({ core, credentials });
        return result(
          await executor.execute({
            taskId: task_id,
            correlationId: correlation_id,
            actorId: actor_id,
          }),
        );
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  server.registerTool(
    "repo.verify_post_merge",
    {
      description:
        "Re-observe the default branch and configured Repo Passport post-merge checks on the exact merge SHA. PENDING keeps POST_MERGE_VERIFY; PASS completes DONE; definitive failures transition fail-closed.",
      inputSchema: z.object({
        task_id: z.string().min(1).max(128),
      }),
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    async ({ task_id }) => {
      try {
        const taskRecord = core.getTask(task_id);
        if (taskRecord.state !== "POST_MERGE_VERIFY") {
          throw new ControllerError(
            "POST_MERGE_VERIFICATION_NOT_READY",
            "Post-merge verification requires POST_MERGE_VERIFY task state",
            { state: taskRecord.state },
          );
        }
        const attempt = core.getPrIntegrationCandidate(task_id);
        if (!attempt.merge_receipt) {
          throw new ControllerError(
            "POST_MERGE_EVIDENCE_MISSING",
            "Post-merge verification requires a persisted trusted merge receipt",
          );
        }
        const passport = core.getPassport(taskRecord.spec.repo_id).passport;
        const credentials = githubCredentialsFromEnvironment();
        const observer = new GitHubPostMergeObserver({ credentials });
        const report = await observer.observe({
          task: taskRecord.spec,
          passport,
          receipt: attempt.merge_receipt,
        });
        if (report.status === "PENDING") {
          return result({
            task: core.getTask(task_id),
            report,
            persisted: false,
          });
        }
        const completed = core.completePostMergeVerification(report);
        return result({ task: completed, report, persisted: true });
      } catch (error) {
        return errorResult(error);
      }
    },
  );

  return server;
}

export async function runStdioServer(): Promise<void> {
  const projectRoot = findProjectRoot();
  const statePath =
    process.env.AWF_STATE_PATH ?? join(projectRoot, ".state", "controller-state.json");
  const backend = loadExecutionBackendConfig();
  const core = new ControllerCore({
    statePath,
    freeModelPolicyPath:
      process.env.AWF_FREE_MODEL_POLICY_PATH ??
      join(projectRoot, "policies", "opencode-free-routing.json"),
    freeModelStatePath:
      process.env.AWF_FREE_MODEL_STATE_PATH ??
      join(projectRoot, ".state", "opencode-free-runtime.json"),
    localVerificationEnabled: true,
    executionBackend: backend.backend,
    ...(backend.backend === "github-actions"
      ? { githubActionsMachineId: backend.machineId }
      : {}),
  });
  if (backend.backend === "github-actions") {
    core.registerMachine(
      githubActionsMachineCapability({
        machineId: backend.machineId,
        maxSlots: backend.maxSlots,
      }),
    );
  }

  await serveStdio(() => buildServer(core));
  console.error(`autonomous-worker-controller MCP stdio ready; state=${statePath}`);
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  void runStdioServer();
}

import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { ControllerCore } from "../controller/controller.js";
import { ControllerError } from "../lib/errors.js";
import {
  prepareGitIntegrationArtifact,
  type PrepareGitIntegrationInput,
} from "./git-integration.js";
import {
  GitHubPullRequestPublisher,
  type ExactCommitPusher,
  type GitHubInstallationTokenProvider,
  type PublishedPullRequest,
} from "./github-write.js";

export interface GitHubPrExecutorOptions {
  core: ControllerCore;
  credentials: GitHubInstallationTokenProvider;
  integrationRoot: string;
  fetch?: typeof fetch;
  pusher?: ExactCommitPusher;
  now?: () => Date;
  prepareIntegration?: typeof prepareGitIntegrationArtifact;
  materialize?: PrepareGitIntegrationInput["materialize"];
}

export class GitHubPrExecutor {
  readonly #core: ControllerCore;
  readonly #credentials: GitHubInstallationTokenProvider;
  readonly #integrationRoot: string;
  readonly #fetch: typeof fetch | undefined;
  readonly #pusher: ExactCommitPusher | undefined;
  readonly #now: (() => Date) | undefined;
  readonly #prepareIntegration: typeof prepareGitIntegrationArtifact;
  readonly #materialize: PrepareGitIntegrationInput["materialize"] | undefined;

  constructor(options: GitHubPrExecutorOptions) {
    this.#core = options.core;
    this.#credentials = options.credentials;
    this.#integrationRoot = resolve(options.integrationRoot);
    this.#fetch = options.fetch;
    this.#pusher = options.pusher;
    this.#now = options.now;
    this.#prepareIntegration =
      options.prepareIntegration ?? prepareGitIntegrationArtifact;
    this.#materialize = options.materialize;
  }

  async execute(input: {
    attemptId: string;
    correlationId: string;
    actorId: string;
  }): Promise<{
    publication: PublishedPullRequest;
    attempt: ReturnType<ControllerCore["getAttempt"]>;
  }> {
    const attempt = this.#core.getAttempt(input.attemptId);
    const task = this.#core.getTask(attempt.task_id).spec;
    this.#core.requestPr(task.task_id, input.correlationId, input.actorId);

    const persistedIntegration = attempt.integration_candidate;
    if (!persistedIntegration) {
      throw new ControllerError(
        "PR_INTEGRATION_CANDIDATE_NOT_READY",
        "PR executor requires persisted deterministic integration artifact",
      );
    }
    if (attempt.pull_request) {
      return {
        publication: attempt.pull_request,
        attempt,
      };
    }

    mkdirSync(this.#integrationRoot, { recursive: true, mode: 0o700 });
    const rootInfo = lstatSync(this.#integrationRoot);
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
      throw new ControllerError(
        "GIT_INTEGRATION_ROOT_INVALID",
        "Trusted PR integration workspace root must be a real directory",
      );
    }

    const source = this.#core.getRepoSource(task.repo_id);
    const destination = mkdtempSync(join(this.#integrationRoot, "publish-"));
    try {
      const reproduced = await this.#prepareIntegration({
        source,
        task,
        attempt,
        destination,
        identity: {
          name: persistedIntegration.author.name,
          email: persistedIntegration.author.email,
        },
        ...(this.#materialize ? { materialize: this.#materialize } : {}),
      });
      if (
        reproduced.artifact_hash !== persistedIntegration.artifact_hash ||
        reproduced.commit_sha !== persistedIntegration.commit_sha ||
        reproduced.tree_sha !== persistedIntegration.tree_sha
      ) {
        throw new ControllerError(
          "PR_INTEGRATION_REPRODUCTION_MISMATCH",
          "Fresh PR workspace did not reproduce persisted deterministic integration artifact",
          {
            expectedArtifactHash: persistedIntegration.artifact_hash,
            actualArtifactHash: reproduced.artifact_hash,
            expectedCommitSha: persistedIntegration.commit_sha,
            actualCommitSha: reproduced.commit_sha,
          },
        );
      }

      const publisher = new GitHubPullRequestPublisher({
        credentials: this.#credentials,
        ...(this.#fetch ? { fetch: this.#fetch } : {}),
        ...(this.#pusher ? { pusher: this.#pusher } : {}),
        ...(this.#now ? { now: this.#now } : {}),
      });
      const publication = await publisher.publish({
        task,
        artifact: reproduced,
        workspace: destination,
      });
      const stored = this.#core.recordPublishedPullRequest(
        attempt.attempt_id,
        publication,
      );
      return { publication, attempt: stored };
    } finally {
      rmSync(destination, { recursive: true, force: true });
    }
  }
}

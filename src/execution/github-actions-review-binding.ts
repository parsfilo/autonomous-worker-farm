import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

export interface GitHubActionsReviewBindingInput {
  reviewId: string;
  taskId: string;
  sourceAttemptId: string;
  candidateHash: string;
  patchSha256: string;
  machineId: string;
  model: string;
  workerRepo: string;
  workflow: string;
  workflowSha: string;
  sourceArtifactId: number;
  sourceArtifactDigest: string;
}

export function githubActionsReviewRequestHash(
  input: GitHubActionsReviewBindingInput,
): string {
  if (
    !input.reviewId ||
    !input.taskId ||
    !input.sourceAttemptId ||
    !/^[0-9a-f]{64}$/.test(input.candidateHash) ||
    !/^[0-9a-f]{64}$/.test(input.patchSha256) ||
    !input.machineId ||
    !input.model.startsWith("opencode/") ||
    !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(input.workerRepo) ||
    !/^[A-Za-z0-9._-]+\.ya?ml$/.test(input.workflow) ||
    !/^[0-9a-f]{40}$/.test(input.workflowSha) ||
    !Number.isInteger(input.sourceArtifactId) ||
    input.sourceArtifactId < 1 ||
    !/^sha256:[0-9a-f]{64}$/.test(input.sourceArtifactDigest)
  ) {
    throw new ControllerError(
      "GITHUB_ACTIONS_REVIEW_BINDING_INVALID",
      "GitHub Actions review request binding input is invalid",
    );
  }
  return sha256CanonicalJson({
    backend: "github-actions-review-v1",
    review_id: input.reviewId,
    task_id: input.taskId,
    source_attempt_id: input.sourceAttemptId,
    candidate_hash: input.candidateHash,
    patch_sha256: input.patchSha256,
    machine_id: input.machineId,
    model: input.model,
    worker_repo: input.workerRepo,
    workflow: input.workflow,
    workflow_sha: input.workflowSha,
    source_artifact_id: input.sourceArtifactId,
    source_artifact_digest: input.sourceArtifactDigest,
    workspace_read_only: true,
  });
}

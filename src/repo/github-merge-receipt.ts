import type { GitHubMergeReceipt } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

function receiptHash(
  receipt: Omit<GitHubMergeReceipt, "receipt_hash"> | GitHubMergeReceipt,
): string {
  const { receipt_hash: _ignored, ...body } = receipt as GitHubMergeReceipt;
  return sha256CanonicalJson(body);
}

export function finalizeGitHubMergeReceipt(
  body: Omit<GitHubMergeReceipt, "receipt_hash">,
  contracts = new ContractRegistry(),
): GitHubMergeReceipt {
  const expectedMatch =
    body.observed_base_sha === null
      ? null
      : body.observed_base_sha === body.merge_sha;
  if (body.base_head_matches_merge !== expectedMatch) {
    throw new ControllerError(
      "GITHUB_MERGE_RECEIPT_INCONSISTENT",
      "base_head_matches_merge must reflect the immediately observed base SHA or null observation",
      {
        mergeSha: body.merge_sha,
        observedBaseSha: body.observed_base_sha,
        baseHeadMatchesMerge: body.base_head_matches_merge,
      },
    );
  }
  const receipt: GitHubMergeReceipt = {
    ...body,
    receipt_hash: receiptHash(body),
  };
  return contracts.validate<GitHubMergeReceipt>(
    "github-merge-receipt",
    receipt,
  );
}

export function verifyGitHubMergeReceipt(
  receipt: GitHubMergeReceipt,
  contracts = new ContractRegistry(),
): GitHubMergeReceipt {
  contracts.validate<GitHubMergeReceipt>("github-merge-receipt", receipt);
  if (receipt.receipt_hash !== receiptHash(receipt)) {
    throw new ControllerError(
      "GITHUB_MERGE_RECEIPT_HASH_MISMATCH",
      "GitHub merge receipt hash mismatch",
    );
  }
  const expectedMatch =
    receipt.observed_base_sha === null
      ? null
      : receipt.observed_base_sha === receipt.merge_sha;
  if (receipt.base_head_matches_merge !== expectedMatch) {
    throw new ControllerError(
      "GITHUB_MERGE_RECEIPT_INCONSISTENT",
      "Persisted merge receipt has inconsistent base-head evidence",
    );
  }
  return receipt;
}

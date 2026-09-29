import type { GitHubActionsExecutionReceipt } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { sha256CanonicalJson } from "../lib/canonical-json.js";
import { ControllerError } from "../lib/errors.js";

function receiptHash(
  receipt:
    | Omit<GitHubActionsExecutionReceipt, "receipt_hash">
    | GitHubActionsExecutionReceipt,
): string {
  const { receipt_hash: _ignored, ...body } =
    receipt as GitHubActionsExecutionReceipt;
  return sha256CanonicalJson(body);
}

export function finalizeGitHubActionsExecutionReceipt(
  body: Omit<GitHubActionsExecutionReceipt, "receipt_hash">,
  contracts = new ContractRegistry(),
): GitHubActionsExecutionReceipt {
  const receipt: GitHubActionsExecutionReceipt = {
    ...body,
    receipt_hash: receiptHash(body),
  };
  return contracts.validate<GitHubActionsExecutionReceipt>(
    "github-actions-execution-receipt",
    receipt,
  );
}

export function verifyGitHubActionsExecutionReceipt(
  input: unknown,
  contracts = new ContractRegistry(),
): GitHubActionsExecutionReceipt {
  const receipt = contracts.validate<GitHubActionsExecutionReceipt>(
    "github-actions-execution-receipt",
    input,
  );
  if (receipt.receipt_hash !== receiptHash(receipt)) {
    throw new ControllerError(
      "GITHUB_ACTIONS_RECEIPT_HASH_MISMATCH",
      "GitHub Actions execution receipt hash mismatch",
    );
  }
  return receipt;
}

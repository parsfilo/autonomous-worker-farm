import type { SandboxAttestation, SandboxRequest, SandboxTier } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { computeSandboxRequestBindingHash } from "./request-binding.js";
import { ControllerError } from "../lib/errors.js";

export interface SandboxVerificationResult {
  valid: true;
  requestHash: string;
  acceptedTier: SandboxTier;
}

function requireEqual(label: string, expected: string, actual: string): void {
  if (expected !== actual) {
    throw new ControllerError("SANDBOX_ATTESTATION_MISMATCH", label + " mismatch", {
      expected,
      actual,
    });
  }
}

export function verifySandboxAttestation(
  requestInput: unknown,
  attestationInput: unknown,
  contracts = new ContractRegistry(),
): SandboxVerificationResult {
  const request = contracts.validate<SandboxRequest>("sandbox-request", requestInput);
  const attestation = contracts.validate<SandboxAttestation>("sandbox-attestation", attestationInput);
  const requestHash = computeSandboxRequestBindingHash(request);

  requireEqual("request_id", request.request_id, attestation.request_id);
  requireEqual("task_id", request.task_id, attestation.task_id);
  requireEqual("attempt_id", request.attempt_id, attestation.attempt_id);
  requireEqual("machine_id", request.machine_id, attestation.machine_id);
  requireEqual("tier", request.tier, attestation.tier);
  requireEqual("image_digest", request.image.digest, attestation.image_digest);
  requireEqual("request_hash", requestHash, attestation.request_hash);

  if (attestation.status !== "PROVISIONED") {
    throw new ControllerError(
      "SANDBOX_NOT_PROVISIONED",
      "Sandbox attestation status is " + attestation.status,
      { rejectionCode: attestation.rejection_code ?? null },
    );
  }

  if (
    attestation.sandbox.remote_git_write_credential_present ||
    attestation.sandbox.docker_socket_present ||
    attestation.sandbox.host_home_mounted
  ) {
    throw new ControllerError(
      "SANDBOX_FORBIDDEN_RESOURCE",
      "Sandbox contains a forbidden authority/resource",
    );
  }

  if (
    !attestation.sandbox.capabilities_dropped ||
    !attestation.sandbox.read_only_rootfs ||
    !attestation.sandbox.no_new_privileges ||
    attestation.sandbox.process_uid <= 0 ||
    attestation.sandbox.process_gid <= 0
  ) {
    throw new ControllerError(
      "SANDBOX_HARDENING_INCOMPLETE",
      "Sandbox process/rootfs/capability hardening is incomplete",
    );
  }

  requireEqual("network_profile", request.network.profile, attestation.sandbox.network_profile);

  if (!attestation.sandbox.network_enforced) {
    throw new ControllerError(
      "SANDBOX_NETWORK_NOT_ENFORCED",
      "Every sandbox network profile requires broker-enforced isolation",
    );
  }

  if (request.network.profile === "none") {
    if (attestation.egress !== null) {
      throw new ControllerError(
        "SANDBOX_EGRESS_UNEXPECTED",
        "network:none must not carry an egress attestation",
      );
    }
  } else {
    const egress = attestation.egress;
    if (!egress) {
      throw new ControllerError(
        "SANDBOX_EGRESS_MISSING",
        "network:brokered requires an egress attestation",
      );
    }
    requireEqual("egress.profile_id", request.network.egress_profile_id ?? "", egress.profile_id);
    requireEqual("egress.profile_hash", request.network.egress_profile_hash ?? "", egress.profile_hash);
    requireEqual("egress.route_id", request.network.route_id ?? "", egress.route_id);
    requireEqual("egress.model", request.network.model ?? "", egress.model);
    const isOpenCodeFreeRoute =
      request.network.route_id === "opencode-free" &&
      request.network.model?.startsWith("opencode/") === true;
    if (
      !egress.direct_egress_blocked ||
      egress.provider_secret_in_worker ||
      (isOpenCodeFreeRoute ? egress.attempt_token_scoped : !egress.attempt_token_scoped)
    ) {
      throw new ControllerError(
        "SANDBOX_EGRESS_NOT_ATTESTED",
        "Brokered egress does not satisfy least-authority requirements",
      );
    }
  }

  if (request.tier === "T1" || request.tier === "T2") {
    if (attestation.broker.kind !== "privileged-docker" && !attestation.sandbox.user_namespace) {
      throw new ControllerError(
        "SANDBOX_TIER_NOT_ATTESTED",
        request.tier + " requires a trusted container broker or user namespace",
      );
    }
    if (!attestation.sandbox.container_runtime) {
      throw new ControllerError(
        "SANDBOX_TIER_NOT_ATTESTED",
        request.tier + " requires an attested container runtime",
      );
    }
    if (
      !attestation.sandbox.seccomp ||
      !attestation.sandbox.apparmor ||
      !attestation.sandbox.cgroups
    ) {
      throw new ControllerError(
        "SANDBOX_TIER_NOT_ATTESTED",
        request.tier + " requires seccomp, AppArmor and cgroup enforcement",
      );
    }
  }

  if (request.tier === "T2") {
    if (!attestation.sandbox.user_namespace) {
      throw new ControllerError(
        "SANDBOX_TIER_NOT_ATTESTED",
        "T2 additionally requires a user namespace in the current v1 policy",
      );
    }
    if (!attestation.sandbox.network_enforced) {
      throw new ControllerError(
        "SANDBOX_TIER_NOT_ATTESTED",
        "T2 requires enforced network policy",
      );
    }
  }

  return {
    valid: true,
    requestHash,
    acceptedTier: request.tier,
  };
}

import type { SandboxAttestation, SandboxRequest } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";
import type {
  SandboxBroker,
  SandboxBrokerCapability,
  SandboxRunHandle,
} from "./broker.js";

export class UnavailableSandboxBroker implements SandboxBroker {
  readonly id = "unavailable";

  async probe(): Promise<SandboxBrokerCapability> {
    return {
      kind: "future",
      build: "unavailable",
      supportedTiers: [],
      networkProfiles: [],
      healthy: false,
    };
  }

  async provision(_request: SandboxRequest): Promise<{
    handle: SandboxRunHandle;
    attestation: SandboxAttestation;
  }> {
    throw new ControllerError(
      "SANDBOX_BROKER_UNAVAILABLE",
      "No trusted sandbox broker is wired; write-capable execution remains disabled.",
    );
  }

  async terminate(_handle: SandboxRunHandle): Promise<SandboxAttestation> {
    throw new ControllerError("SANDBOX_BROKER_UNAVAILABLE", "No sandbox run exists.");
  }
}

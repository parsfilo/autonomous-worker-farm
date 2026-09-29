import type { SandboxAttestation, SandboxRequest } from "../../contracts/types.js";

export interface SandboxBrokerCapability {
  kind: "local-landlock" | "privileged-docker" | "future";
  build: string;
  supportedTiers: Array<"T0" | "T1" | "T2">;
  networkProfiles: Array<"none" | "brokered">;
  healthy: boolean;
}

export interface SandboxRunHandle {
  requestId: string;
  attemptId: string;
  opaqueHandle: string;
}

export interface SandboxBroker {
  readonly id: string;

  probe(): Promise<SandboxBrokerCapability>;
  provision(request: SandboxRequest): Promise<{ handle: SandboxRunHandle; attestation: SandboxAttestation }>;
  terminate(handle: SandboxRunHandle): Promise<SandboxAttestation>;
}

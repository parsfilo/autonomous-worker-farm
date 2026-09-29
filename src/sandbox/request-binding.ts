import { createHash } from "node:crypto";
import type { SandboxRequest } from "../../contracts/types.js";

function numberText(value: number): string {
  if (!Number.isFinite(value)) throw new TypeError("sandbox binding rejects non-finite numbers");
  return String(value);
}

function field(name: string, value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  const prefix = Buffer.from(name + "=" + bytes.length + ":", "utf8");
  return Buffer.concat([prefix, bytes, Buffer.from("\n")]);
}

export function sandboxRequestBindingBytes(request: SandboxRequest): Buffer {
  const parts: Buffer[] = [Buffer.from("awf-sandbox-request-v1\n", "utf8")];
  const add = (name: string, value: string) => parts.push(field(name, value));

  add("schema_version", request.schema_version);
  add("request_id", request.request_id);
  add("task_id", request.task_id);
  add("attempt_id", request.attempt_id);
  add("machine_id", request.machine_id);
  add("tier", request.tier);
  add("run_root", request.run_root);

  add("workspace.source", request.workspace.source);
  add("workspace.mount_path", request.workspace.mount_path);
  add("workspace.read_only", request.workspace.read_only ? "1" : "0");
  add("workspace.base_sha", request.workspace.base_sha);
  add("workspace.controller_gid", String(request.workspace.controller_gid));

  add("image.reference", request.image.reference);
  add("image.digest", request.image.digest);

  add("network.profile", request.network.profile);
  add("network.egress_profile_id", request.network.egress_profile_id ?? "<null>");
  add("network.egress_profile_hash", request.network.egress_profile_hash ?? "<null>");
  add("network.route_id", request.network.route_id ?? "<null>");
  add("network.model", request.network.model ?? "<null>");

  add("resources.cpu", numberText(request.resources.cpu));
  add("resources.memory_bytes", String(request.resources.memory_bytes));
  add("resources.pids", String(request.resources.pids));
  add("resources.tmpfs_bytes", String(request.resources.tmpfs_bytes));
  add("resources.timeout_seconds", String(request.resources.timeout_seconds));

  add("command.argv.count", String(request.command.argv.length));
  request.command.argv.forEach((value, index) => add("command.argv." + index, value));
  add("command.env_allowlist.count", String(request.command.env_allowlist.length));
  request.command.env_allowlist.forEach((value, index) => add("command.env_allowlist." + index, value));

  add("policy_hash", request.policy_hash);
  add("expires_at", request.expires_at);
  add("workspace_lease_id", request.workspace_lease_id);
  add("workspace_lease_hash", request.workspace_lease_hash);

  return Buffer.concat(parts);
}

export function computeSandboxRequestBindingHash(request: SandboxRequest): string {
  return createHash("sha256").update(sandboxRequestBindingBytes(request)).digest("hex");
}

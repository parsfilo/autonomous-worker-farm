import { createHash } from "node:crypto";
import { posix } from "node:path";
import type { EgressProfile, SandboxRequest } from "../../contracts/types.js";
import { ContractRegistry } from "../contracts/schema-validator.js";
import { ControllerError } from "../lib/errors.js";

export interface ResolvedEgressRoute {
  profile: EgressProfile;
  profileHash: string;
  route: EgressProfile["routes"][number];
  model: string;
  workerBaseURL: string;
  openCodeProvider: {
    model: string;
    providers: Record<string, unknown>;
  } | null;
  proxyURL: string | null;
}

const PACKAGE_BY_PROTOCOL = {
  "openai-responses": "@opencode/ai/providers/openai/responses",
  "openai-chat": "@opencode/ai/providers/openai/chat",
  "openai-compatible": "@opencode/ai/providers/openai-compatible",
  "openai-compatible-responses": "@opencode/ai/providers/openai-compatible/responses",
  anthropic: "@opencode/ai/providers/anthropic",
} as const;

function validateOrigin(value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (error) {
    throw new ControllerError("EGRESS_PROFILE_INVALID", "upstream_base_url is not a valid URL", {
      value,
      cause: error instanceof Error ? error.message : String(error),
    });
  }
  if (
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.pathname !== "/" && parsed.pathname !== "")
  ) {
    throw new ControllerError(
      "EGRESS_PROFILE_INVALID",
      "upstream_base_url must be an HTTPS origin without path, query, fragment or userinfo",
      { value },
    );
  }
}

function validateWorkerBasePath(value: string): void {
  if (!value.startsWith("/") || value.includes("\\") || value.includes("?") || value.includes("#")) {
    throw new ControllerError("EGRESS_PROFILE_INVALID", "worker_base_path is invalid", { value });
  }
  if (posix.normalize(value) !== value || value.split("/").includes("..")) {
    throw new ControllerError("EGRESS_PROFILE_INVALID", "worker_base_path must be canonical", { value });
  }
}

function validateAuthBinding(
  kind: "bearer" | "header" | "none",
  headerName: string,
  label: string,
): void {
  if (kind === "none") {
    if (headerName !== "") {
      throw new ControllerError(
        "EGRESS_PROFILE_INVALID",
        label + " none auth must use an empty header_name",
      );
    }
    return;
  }
  if (!/^[A-Za-z0-9-]{1,128}$/.test(headerName)) {
    throw new ControllerError("EGRESS_PROFILE_INVALID", label + " auth header is invalid");
  }
  if (kind === "bearer" && headerName.toLowerCase() !== "authorization") {
    throw new ControllerError(
      "EGRESS_PROFILE_INVALID",
      label + " bearer auth must use the Authorization header",
    );
  }
}

function validateSecretHandle(value: string): void {
  if (!value.startsWith("secret://")) {
    throw new ControllerError(
      "EGRESS_PROFILE_INVALID",
      "secret_handle must use the secret:// scheme",
    );
  }
  const relative = value.slice("secret://".length);
  const parts = relative.split("/");
  if (
    parts.length === 0 ||
    parts.some((part) => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(part))
  ) {
    throw new ControllerError(
      "EGRESS_PROFILE_INVALID",
      "secret_handle contains an invalid path component",
    );
  }
}

export function validateEgressProfile(
  input: unknown,
  contracts = new ContractRegistry(),
): EgressProfile {
  const profile = contracts.validate<EgressProfile>("egress-profile", input);
  if (
    profile.package_proxy.enabled ||
    profile.package_proxy.allowed_hosts.length > 0 ||
    profile.package_proxy.allowed_ports.length > 0
  ) {
    throw new ControllerError(
      "EGRESS_PACKAGE_PROXY_UNIMPLEMENTED",
      "Generic package/CONNECT proxy is not implemented",
    );
  }

  const hasFreeConnectRoute = profile.routes.some(
    (route) => route.protocol === "opencode-free-connect",
  );
  if (hasFreeConnectRoute && profile.internal_network.http_proxy_port === null) {
    throw new ControllerError(
      "EGRESS_PROFILE_INVALID",
      "opencode-free-connect requires internal_network.http_proxy_port",
    );
  }
  if (!hasFreeConnectRoute && profile.internal_network.http_proxy_port !== null) {
    throw new ControllerError(
      "EGRESS_PACKAGE_PROXY_UNIMPLEMENTED",
      "http_proxy_port is reserved for opencode-free-connect",
    );
  }

  const routeIds = new Set<string>();
  for (const route of profile.routes) {
    if (routeIds.has(route.route_id)) {
      throw new ControllerError("EGRESS_PROFILE_INVALID", "duplicate egress route_id", {
        routeId: route.route_id,
      });
    }
    routeIds.add(route.route_id);
    validateOrigin(route.upstream_base_url);
    validateWorkerBasePath(route.worker_base_path);

    const models = new Set(route.models);
    if (models.size !== route.models.length) {
      throw new ControllerError("EGRESS_PROFILE_INVALID", "duplicate model in egress route", {
        routeId: route.route_id,
      });
    }

    if (route.protocol === "opencode-free-connect") {
      if (
        route.route_id !== "opencode-free" ||
        route.provider_id !== "opencode" ||
        route.upstream_base_url !== "https://opencode.ai" ||
        route.worker_base_path !== "/" ||
        route.worker_auth.kind !== "none" ||
        route.worker_auth.header_name !== "" ||
        route.worker_auth.secret_file !== null ||
        route.upstream_auth.kind !== "none" ||
        route.upstream_auth.header_name !== "" ||
        route.secret_handle !== null ||
        route.models.length !== 1 ||
        route.models[0] !== "opencode/*" ||
        route.request_path_prefixes.length !== 0
      ) {
        throw new ControllerError(
          "EGRESS_PROFILE_INVALID",
          "opencode-free-connect route must be anonymous, secretless, host-pinned and namespace-limited",
          { routeId: route.route_id },
        );
      }
      continue;
    }

    validateAuthBinding(route.worker_auth.kind, route.worker_auth.header_name, "worker_auth");
    validateAuthBinding(route.upstream_auth.kind, route.upstream_auth.header_name, "upstream_auth");
    if (route.worker_auth.kind === "none" || route.upstream_auth.kind === "none") {
      throw new ControllerError(
        "EGRESS_PROFILE_INVALID",
        "secret-backed routes cannot use auth kind none",
      );
    }
    if (route.worker_auth.secret_file !== "/run/egress/attempt-token") {
      throw new ControllerError(
        "EGRESS_PROFILE_INVALID",
        "secret-backed route must use the fixed attempt-token file",
      );
    }
    if (route.secret_handle === null) {
      throw new ControllerError(
        "EGRESS_PROFILE_INVALID",
        "secret-backed route requires secret_handle",
      );
    }
    validateSecretHandle(route.secret_handle);
    if (route.request_path_prefixes.length === 0) {
      throw new ControllerError(
        "EGRESS_PROFILE_INVALID",
        "secret-backed route requires request path prefixes",
      );
    }
  }

  return profile;
}

function bindingField(name: string, value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([
    Buffer.from(name + "=" + bytes.length + ":", "utf8"),
    bytes,
    Buffer.from("\n", "utf8"),
  ]);
}

export function egressProfileBindingBytes(profile: EgressProfile): Buffer {
  const parts: Buffer[] = [Buffer.from("awf-egress-profile-v1\n", "utf8")];
  const add = (name: string, value: string) => parts.push(bindingField(name, value));
  const boolText = (value: boolean) => (value ? "1" : "0");

  add("schema_version", profile.schema_version);
  add("profile_id", profile.profile_id);
  add("revision", String(profile.revision));
  add("gateway_image.reference", profile.gateway_image.reference);
  add("gateway_image.digest", profile.gateway_image.digest);
  add("internal_network.gateway_alias", profile.internal_network.gateway_alias);
  add("internal_network.llm_port", String(profile.internal_network.llm_port));
  add(
    "internal_network.http_proxy_port",
    profile.internal_network.http_proxy_port === null
      ? "<null>"
      : String(profile.internal_network.http_proxy_port),
  );
  add(
    "internal_network.direct_egress_denied",
    boolText(profile.internal_network.direct_egress_denied),
  );

  add("routes.count", String(profile.routes.length));
  profile.routes.forEach((route, routeIndex) => {
    const prefix = "routes." + routeIndex + ".";
    add(prefix + "route_id", route.route_id);
    add(prefix + "provider_id", route.provider_id);
    add(prefix + "protocol", route.protocol);
    add(prefix + "upstream_base_url", route.upstream_base_url);
    add(prefix + "worker_base_path", route.worker_base_path);
    add(prefix + "worker_auth.kind", route.worker_auth.kind);
    add(prefix + "worker_auth.header_name", route.worker_auth.header_name);
    add(prefix + "worker_auth.secret_file", route.worker_auth.secret_file ?? "<null>");
    add(prefix + "upstream_auth.kind", route.upstream_auth.kind);
    add(prefix + "upstream_auth.header_name", route.upstream_auth.header_name);
    add(prefix + "secret_handle", route.secret_handle ?? "<null>");

    add(prefix + "models.count", String(route.models.length));
    route.models.forEach((model, index) => add(prefix + "models." + index, model));

    add(prefix + "request_path_prefixes.count", String(route.request_path_prefixes.length));
    route.request_path_prefixes.forEach((value, index) =>
      add(prefix + "request_path_prefixes." + index, value),
    );
  });

  add("package_proxy.enabled", boolText(profile.package_proxy.enabled));
  add("package_proxy.allowed_hosts.count", String(profile.package_proxy.allowed_hosts.length));
  profile.package_proxy.allowed_hosts.forEach((host, index) =>
    add("package_proxy.allowed_hosts." + index, host),
  );
  add("package_proxy.allowed_ports.count", String(profile.package_proxy.allowed_ports.length));
  profile.package_proxy.allowed_ports.forEach((port, index) =>
    add("package_proxy.allowed_ports." + index, String(port)),
  );

  add("limits.max_request_bytes", String(profile.limits.max_request_bytes));
  add("limits.max_response_bytes", String(profile.limits.max_response_bytes));
  add("limits.max_concurrent_requests", String(profile.limits.max_concurrent_requests));
  add("policy_revision", String(profile.policy_revision));

  return Buffer.concat(parts);
}

export function computeEgressProfileHash(
  input: unknown,
  contracts = new ContractRegistry(),
): string {
  const profile = validateEgressProfile(input, contracts);
  return createHash("sha256").update(egressProfileBindingBytes(profile)).digest("hex");
}

export function resolveEgressRoute(
  input: unknown,
  routeId: string,
  model: string,
  contracts = new ContractRegistry(),
): ResolvedEgressRoute {
  const profile = validateEgressProfile(input, contracts);
  const route = profile.routes.find((entry) => entry.route_id === routeId);
  if (!route) {
    throw new ControllerError("EGRESS_ROUTE_NOT_FOUND", "Egress route is not present in trusted profile", {
      routeId,
    });
  }
  const isFreeConnect = route.protocol === "opencode-free-connect";
  const modelAllowed = isFreeConnect
    ? route.models.includes("opencode/*") &&
      /^opencode\/[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(model)
    : route.models.includes(model);
  if (!modelAllowed) {
    throw new ControllerError("EGRESS_MODEL_FORBIDDEN", "Model is not allowed by selected egress route", {
      routeId,
      model,
    });
  }

  if (isFreeConnect) {
    const proxyPort = profile.internal_network.http_proxy_port;
    if (proxyPort === null) {
      throw new ControllerError(
        "EGRESS_PROFILE_INVALID",
        "opencode-free-connect profile is missing http_proxy_port",
      );
    }
    return {
      profile,
      profileHash: computeEgressProfileHash(profile, contracts),
      route,
      model,
      workerBaseURL: "",
      openCodeProvider: null,
      proxyURL:
        "http://" + profile.internal_network.gateway_alias + ":" + String(proxyPort),
    };
  }

  const providerId = "awf";
  const workerBaseURL =
    "http://" +
    profile.internal_network.gateway_alias +
    ":" +
    profile.internal_network.llm_port +
    route.worker_base_path;

  const providerPackage = PACKAGE_BY_PROTOCOL[route.protocol as keyof typeof PACKAGE_BY_PROTOCOL];
  const secretFile = route.worker_auth.secret_file;
  if (!secretFile) {
    throw new ControllerError("EGRESS_PROFILE_INVALID", "secret-backed route lost secret_file");
  }
  const openCodeProvider = {
    model: providerId + "/" + model,
    providers: {
      [providerId]: {
        name: "AWF Trusted Gateway",
        package: providerPackage,
        settings: {
          baseURL: workerBaseURL,
          apiKey: "{file:" + secretFile + "}",
        },
        models: {
          [model]: {
            modelID: model,
          },
        },
      },
    },
  };

  return {
    profile,
    profileHash: computeEgressProfileHash(profile, contracts),
    route,
    model,
    workerBaseURL,
    openCodeProvider,
    proxyURL: null,
  };
}

export function verifyRequestEgressBinding(
  request: SandboxRequest,
  input: unknown,
  contracts = new ContractRegistry(),
): ResolvedEgressRoute | null {
  if (request.network.profile === "none") {
    if (
      request.network.egress_profile_id !== null ||
      request.network.egress_profile_hash !== null ||
      request.network.route_id !== null ||
      request.network.model !== null
    ) {
      throw new ControllerError(
        "EGRESS_REQUEST_BINDING_INVALID",
        "network:none must not bind an egress profile",
      );
    }
    return null;
  }

  const routeId = request.network.route_id;
  const model = request.network.model;
  if (!routeId || !model) {
    throw new ControllerError(
      "EGRESS_REQUEST_BINDING_INVALID",
      "brokered request is missing route_id or model",
    );
  }
  const resolved = resolveEgressRoute(input, routeId, model, contracts);
  if (request.network.egress_profile_id !== resolved.profile.profile_id) {
    throw new ControllerError(
      "EGRESS_REQUEST_BINDING_MISMATCH",
      "SandboxRequest egress_profile_id does not match trusted profile",
    );
  }
  if (request.network.egress_profile_hash !== resolved.profileHash) {
    throw new ControllerError(
      "EGRESS_REQUEST_BINDING_MISMATCH",
      "SandboxRequest egress_profile_hash does not match trusted profile",
    );
  }
  return resolved;
}

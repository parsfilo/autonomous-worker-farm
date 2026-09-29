import {
  createControllerMcpHttpServer,
  defaultControllerStatePath,
  loadControllerMcpToken,
} from "../mcp/http-server.js";

const host = process.env.AWF_CONTROLLER_MCP_HOST ?? "127.0.0.1";
const port = Number.parseInt(process.env.AWF_CONTROLLER_MCP_PORT ?? "18777", 10);
const statePath = process.env.AWF_STATE_PATH ?? defaultControllerStatePath();
const tokenFile = process.env.AWF_CONTROLLER_MCP_TOKEN_FILE;
const freeModelPolicyPath = process.env.AWF_FREE_MODEL_POLICY_PATH;
const freeModelStatePath = process.env.AWF_FREE_MODEL_STATE_PATH;

if (!Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error("AWF_CONTROLLER_MCP_PORT must be 1024..65535");
}
if (!tokenFile) {
  throw new Error("AWF_CONTROLLER_MCP_TOKEN_FILE is required");
}

const server = createControllerMcpHttpServer({
  statePath,
  token: loadControllerMcpToken(tokenFile),
  host,
  port,
  ...(freeModelPolicyPath ? { freeModelPolicyPath } : {}),
  ...(freeModelStatePath ? { freeModelStatePath } : {}),
});

server.listen(port, host, () => {
  console.error(
    `autonomous-worker-controller MCP HTTP ready; http://${host}:${port}/mcp state=${statePath}`,
  );
});

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}

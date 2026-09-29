import {
  type JSONRPCMessage,
  type JSONRPCRequest,
} from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { pathToFileURL } from "node:url";

const REQUIRED_URL = "http://127.0.0.1:18777/mcp";

export interface ControllerProxyConfig {
  url: string;
  token: string;
}

export function controllerProxyConfigFromEnvironment(
  env: NodeJS.ProcessEnv = process.env,
): ControllerProxyConfig {
  const url = env.AWF_CONTROLLER_MCP_URL?.trim() ?? "";
  const token = env.AWF_CONTROLLER_MCP_TOKEN?.trim() ?? "";
  if (url !== REQUIRED_URL) {
    throw new Error("AWF controller stdio proxy requires the exact loopback Controller MCP URL");
  }
  if (token.length < 32) {
    throw new Error("AWF controller stdio proxy requires a non-empty trusted bearer token");
  }
  return { url, token };
}

export function decodeControllerHttpResponse(
  body: string,
  contentType: string | null,
): JSONRPCMessage[] {
  const trimmed = body.trim();
  if (!trimmed) return [];

  const payloads =
    contentType?.toLowerCase().includes("text/event-stream") ||
    trimmed.startsWith("event:") ||
    trimmed.startsWith("data:")
      ? trimmed
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trim())
          .filter(Boolean)
      : [trimmed];

  return payloads.map((payload) => JSON.parse(payload) as JSONRPCMessage);
}

function errorResponse(message: JSONRPCMessage, detail: string): JSONRPCMessage | null {
  if (!("id" in message) || message.id === undefined) return null;
  return {
    jsonrpc: "2.0",
    id: message.id,
    error: {
      code: -32603,
      message: "Trusted Controller MCP proxy request failed",
      data: { detail },
    },
  };
}

export async function forwardControllerMessage(
  message: JSONRPCMessage,
  config: ControllerProxyConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<JSONRPCMessage[]> {
  let response: Response;
  try {
    response = await fetchImpl(config.url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify(message),
      redirect: "error",
    });
  } catch (error) {
    const failure = errorResponse(
      message,
      error instanceof Error ? error.message : String(error),
    );
    return failure ? [failure] : [];
  }

  const body = await response.text();
  if (response.status === 202 || response.status === 204) return [];
  if (!response.ok) {
    const failure = errorResponse(
      message,
      `HTTP ${response.status}: ${body.slice(0, 500)}`,
    );
    return failure ? [failure] : [];
  }

  try {
    return decodeControllerHttpResponse(
      body,
      response.headers.get("content-type"),
    );
  } catch (error) {
    const failure = errorResponse(
      message,
      error instanceof Error ? error.message : String(error),
    );
    return failure ? [failure] : [];
  }
}

export async function runControllerMcpStdioProxy(): Promise<void> {
  const config = controllerProxyConfigFromEnvironment();
  const transport = new StdioServerTransport(process.stdin, process.stdout, {
    maxBufferSize: 4 * 1024 * 1024,
  });

  let queue = Promise.resolve();
  transport.onmessage = (message) => {
    queue = queue.then(async () => {
      const responses = await forwardControllerMessage(message, config);
      for (const response of responses) {
        await transport.send(response);
      }
    });
    queue.catch((error) => {
      process.stderr.write(
        `AWF_CONTROLLER_STDIO_PROXY_ERROR ${error instanceof Error ? error.message : String(error)}\n`,
      );
    });
  };
  transport.onerror = (error) => {
    process.stderr.write(`AWF_CONTROLLER_STDIO_PROXY_TRANSPORT_ERROR ${error.message}\n`);
  };

  await transport.start();
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  void runControllerMcpStdioProxy();
}

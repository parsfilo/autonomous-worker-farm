import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export function findProjectRoot(startUrl: string = import.meta.url): string {
  const fromEnv = process.env.AWF_PROJECT_ROOT;
  if (fromEnv) return fromEnv;

  let current = dirname(fileURLToPath(startUrl));
  for (let i = 0; i < 8; i += 1) {
    if (existsSync(join(current, "package.json")) && existsSync(join(current, "contracts"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new Error("Unable to locate autonomous-worker project root");
}

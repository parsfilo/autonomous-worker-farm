import { join } from "node:path";
import { ControllerCore } from "../controller/controller.js";
import { findProjectRoot } from "../lib/project-root.js";
import { probeLocalMachine } from "../machine/probe.js";

const root = findProjectRoot();
const machineId = process.argv[2] ?? "production-vps";
const machine = await probeLocalMachine(machineId);

const statePath = process.env.AWF_STATE_PATH ?? join(root, ".state", "controller-state.json");
const core = new ControllerCore({ statePath });
const registered = core.registerMachine(machine);

process.stdout.write(JSON.stringify(registered, null, 2) + "\n");

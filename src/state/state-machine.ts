import type { TaskState } from "../../contracts/types.js";
import { ControllerError } from "../lib/errors.js";

const allowedTransitions: Record<TaskState, readonly TaskState[]> = {
  CREATED: ["PLANNED", "CANCELLED"],
  PLANNED: ["READY", "EXTERNAL_BLOCKER", "CANCELLED"],
  READY: ["LEASED", "NO_CAPACITY", "MACHINE_OFFLINE", "MODEL_RATE_LIMITED", "CANCELLED"],
  LEASED: ["PROVISIONING", "BASE_DRIFT", "LOST", "MACHINE_OFFLINE", "CANCELLED"],
  PROVISIONING: ["RUNNING", "HARNESS_FAILED", "POLICY_VIOLATION", "MACHINE_OFFLINE", "LOST", "CANCELLED"],
  RUNNING: [
    "EVIDENCE_COLLECT",
    "HARNESS_FAILED",
    "MODEL_RATE_LIMITED",
    "POLICY_VIOLATION",
    "TEST_FAILED",
    "LOST",
    "CANCELLED",
  ],
  EVIDENCE_COLLECT: ["LOCAL_VERIFY", "HARNESS_FAILED", "POLICY_VIOLATION", "LOST", "CANCELLED"],
  LOCAL_VERIFY: ["CANDIDATE", "TEST_FAILED", "QUALITY_FAILED", "POLICY_VIOLATION", "BASE_DRIFT", "CANCELLED"],
  CANDIDATE: ["INDEPENDENT_REVIEW", "BASE_DRIFT", "CANCELLED"],
  INDEPENDENT_REVIEW: ["REMOTE_VERIFY", "REVIEW_BLOCKED", "BASE_DRIFT", "CANCELLED"],
  REMOTE_VERIFY: ["READY_TO_MERGE", "QUALITY_FAILED", "BASE_DRIFT", "EXTERNAL_BLOCKER", "CANCELLED"],
  READY_TO_MERGE: ["MERGING", "BASE_DRIFT", "EXTERNAL_BLOCKER", "CANCELLED"],
  MERGING: ["POST_MERGE_VERIFY", "EXTERNAL_BLOCKER"],
  POST_MERGE_VERIFY: ["DONE", "QUALITY_FAILED", "EXTERNAL_BLOCKER"],

  NO_CAPACITY: ["READY", "CANCELLED"],
  MACHINE_OFFLINE: ["READY", "CANCELLED"],
  MODEL_RATE_LIMITED: ["READY", "CANCELLED"],
  HARNESS_FAILED: ["READY", "CANCELLED"],
  TEST_FAILED: ["READY", "CANCELLED"],
  QUALITY_FAILED: ["READY", "CANCELLED"],
  REVIEW_BLOCKED: ["READY", "CANCELLED"],
  BASE_DRIFT: ["PLANNED", "CANCELLED"],
  EXTERNAL_BLOCKER: ["PLANNED", "READY", "CANCELLED"],
  LOST: ["READY", "CANCELLED"],

  POLICY_VIOLATION: ["CANCELLED"],
  DONE: [],
  CANCELLED: [],
};

export function canTransition(from: TaskState, to: TaskState): boolean {
  return allowedTransitions[from].includes(to);
}

export function assertTransition(from: TaskState, to: TaskState): void {
  if (!canTransition(from, to)) {
    throw new ControllerError("INVALID_STATE_TRANSITION", `Task state transition ${from} -> ${to} is not allowed`, {
      from,
      to,
    });
  }
}

export function allowedNextStates(from: TaskState): readonly TaskState[] {
  return allowedTransitions[from];
}

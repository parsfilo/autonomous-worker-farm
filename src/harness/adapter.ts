import type { HarnessCapability, RepoPassport, ResultManifest, TaskSpec } from "../../contracts/types.js";

export interface ResolvedExecutionPolicy {
  model?: string;
  openCodeProvider?: {
    model: string;
    providers: Record<string, unknown>;
  };
  proxyURL?: string;
  shellAllowlist: string[];
  approvedSkillIds: string[];
  allowedMcpActions?: string[];
  readOnlyReviewMode?: boolean;
}

export interface HarnessPrepareContext {
  task: TaskSpec;
  passport: RepoPassport;
  runRoot: string;
  policy: ResolvedExecutionPolicy;
}

export interface PreparedRun {
  runRoot: string;
  workingDirectory: string;
  environment: Record<string, string>;
  metadata: Record<string, unknown>;
}

export interface HarnessRunHandle {
  id: string;
  startedAt: string;
}

export interface HarnessAdapter {
  readonly id: string;

  probe(): Promise<HarnessCapability>;
  prepare(context: HarnessPrepareContext): Promise<PreparedRun>;
  execute(prepared: PreparedRun, task: TaskSpec): Promise<HarnessRunHandle>;
  cancel(run: HarnessRunHandle): Promise<void>;
  collectEvidence(run: HarnessRunHandle): Promise<Partial<ResultManifest>>;
  cleanup(prepared: PreparedRun): Promise<void>;
}

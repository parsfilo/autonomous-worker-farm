// Reference types for Phase 0/1 contracts.
// JSON Schemas are normative; these TypeScript types are developer ergonomics.

export type RiskClass = "LOW" | "MEDIUM" | "HIGH" | "PROTECTED";
export type SandboxTier = "T0" | "T1" | "T2";
export type ModelClass = "fast" | "coding" | "deep-reasoning" | "review" | "frontier";

export type WorkerArchetype =
  | "scout"
  | "architect"
  | "builder"
  | "test-engineer"
  | "ci-doctor"
  | "quality-security"
  | "independent-reviewer"
  | "domain-specialist";

export type TaskState =
  | "CREATED"
  | "PLANNED"
  | "READY"
  | "LEASED"
  | "PROVISIONING"
  | "RUNNING"
  | "EVIDENCE_COLLECT"
  | "LOCAL_VERIFY"
  | "CANDIDATE"
  | "INDEPENDENT_REVIEW"
  | "REMOTE_VERIFY"
  | "READY_TO_MERGE"
  | "MERGING"
  | "POST_MERGE_VERIFY"
  | "DONE"
  | "NO_CAPACITY"
  | "MACHINE_OFFLINE"
  | "MODEL_RATE_LIMITED"
  | "HARNESS_FAILED"
  | "POLICY_VIOLATION"
  | "TEST_FAILED"
  | "QUALITY_FAILED"
  | "REVIEW_BLOCKED"
  | "BASE_DRIFT"
  | "EXTERNAL_BLOCKER"
  | "LOST"
  | "CANCELLED";

export interface VersionedRef {
  id: string;
  version: string;
  sha256: string;
}

export interface TaskSpec {
  schema_version: "1.0";
  task_id: string;
  task_revision?: number;
  project_id: string;
  repo_id: string;
  objective: string;
  acceptance_criteria: string[];
  base_ref: string;
  base_sha: string;
  archetype: WorkerArchetype;
  capability_modifiers?: string[];
  risk_class: RiskClass;
  read_scope: string[];
  write_scope: string[];
  protected_paths: string[];
  denied_paths: string[];
  network_profile: string;
  tool_profile: string;
  approved_skills: VersionedRef[];
  harness_requirements: {
    allowed_adapters?: string[];
    required_capabilities: string[];
    minimum_sandbox_tier?: SandboxTier;
  };
  model_requirements: {
    class: ModelClass;
    provider_diversity_from_attempt_id?: string | null;
    minimum_context_tokens?: number;
    privacy_class?: "public" | "private" | "restricted";
  };
  timeout_seconds: number;
  lease_ttl_seconds: number;
  heartbeat_interval_seconds: number;
  max_attempts: number;
  evidence_requirements: string[];
  quality_profile: string;
  review_policy: {
    independent_review: boolean;
    require_provider_diversity?: boolean;
    human_approval_required?: boolean;
  };
  repo_passport_hash: string;
  context_snapshot_hash: string;
  causation_id?: string | null;
  correlation_id?: string | null;
}



export interface IndependentReviewFinding {
  severity: "BLOCKING" | "NON_BLOCKING";
  code: string;
  summary: string;
  path: string | null;
  line: number | null;
}

export interface IndependentReviewReport {
  schema_version: "1.0";
  review_id: string;
  task_id: string;
  source_attempt_id: string;
  review_attempt_id: string;
  candidate_hash: string;
  patch_sha256: string;
  base_sha: string;
  verdict: "PASS" | "BLOCK";
  findings: IndependentReviewFinding[];
  summary: string;
  reviewer: {
    machine_id: string;
    provider: "opencode";
    model: string;
    harness_adapter: "opencode";
    harness_version: string;
  };
  sandbox: {
    tier: "T1";
    request_hash: string;
    image_digest: string;
    network_profile: "brokered";
    workspace_read_only: true;
  };
  started_at: string;
  ended_at: string;
  raw_output_sha256: string;
  report_hash: string;
}

export interface GateEvidence {
  status: "PASS" | "FAIL" | "SKIP" | "NOT_APPLICABLE" | "ERROR" | "MISSING";
  exit_code?: number | null;
  report_sha256?: string | null;
  report_uri?: string | null;
  details?: Record<string, unknown> | null;
}

export interface ResultManifest {
  schema_version: "1.0";
  task_id: string;
  attempt_id: string;
  attempt_no: number;
  base_sha: string;
  repo_passport_hash: string;
  context_snapshot_hash: string;
  machine: { machine_id: string; os?: string; kernel?: string };
  sandbox: {
    tier: SandboxTier;
    attested: boolean;
    landlock_abi?: number | null;
    container_runtime?: string | null;
    container_image_digest?: string | null;
  };
  harness: {
    adapter: string;
    version: string;
    digest?: string | null;
    session_id?: string | null;
  };
  model: { provider: string; model: string; request_ids?: string[] };
  approved_skills?: VersionedRef[];
  tool_versions?: Record<string, string>;
  started_at: string;
  ended_at: string;
  status: "SUCCEEDED" | "FAILED" | "CANCELLED" | "LOST" | "POLICY_VIOLATION";
  changed_files: string[];
  patch_sha256?: string | null;
  candidate_hash: string;
  candidate_commit_sha?: string | null;
  commands: unknown[];
  checks: {
    format: GateEvidence;
    lint: GateEvidence;
    typecheck: GateEvidence;
    build: GateEvidence;
    secret_scan: GateEvidence;
  };
  tests: GateEvidence[];
  lsp_diagnostics?: unknown[];
  quality: {
    semgrep: GateEvidence;
    codacy: GateEvidence;
    sonar: GateEvidence;
  };
  policy_events: unknown[];
  network_events: unknown[];
  artifacts: unknown[];
  summary?: string | null;
}

export interface RepoPassport {
  schema_version: "1.0";
  repo_id: string;
  visibility: "public" | "private" | "internal";
  trust_tier: RiskClass;
  default_branch: string;
  protected_paths: string[];
  generated_paths: string[];
  vendor_paths: string[];
  languages: string[];
  frameworks: string[];
  allowed_build_commands: string[][];
  allowed_test_commands: string[][];
  quality: Record<
    "format" | "lint" | "typecheck" | "build" | "tests" | "secret_scan" | "semgrep" | "codacy" | "sonar",
    { required: boolean; profile?: string | null }
  >;
  network_profiles: string[];
  max_parallel_tasks: number;
  max_open_prs: number;
  allowed_harnesses: string[];
  allowed_model_classes: ModelClass[];
  independent_review_required: boolean;
  merge_method: "squash" | "merge" | "rebase" | "fast-forward";
  post_merge_checks: string[];
  policy_revision?: number;
}

export interface MachineHarnessCapability {
  adapter: string;
  version: string;
  digest?: string | null;
  healthy: boolean;
  capabilities: string[];
}

export interface MachineCapability {
  schema_version: "1.0";
  machine_id: string;
  online: boolean;
  os: string;
  architecture: string;
  kernel?: string | null;
  cpu_logical: number;
  memory_bytes: number;
  disk_free_bytes: number;
  disk_total_bytes?: number;
  disk_used_percent?: number;
  sandbox: {
    landlock: boolean;
    landlock_abi?: number | null;
    rootless_container: boolean;
    container_runtime?: string | null;
    cgroups: boolean;
    seccomp: boolean;
    network_policy: boolean;
  };
  harnesses: MachineHarnessCapability[];
  tools: Record<string, string>;
  tool_profiles: string[];
  network_profiles: string[];
  model_classes: ModelClass[];
  max_slots: number;
  active_slots?: number;
  trust_ceiling: RiskClass;
  last_probe_at?: string | null;
}

export interface HarnessCapability {
  schema_version: "1.0";
  adapter: string;
  version: string;
  digest?: string | null;
  capabilities: string[];
  repo_config_quarantine: {
    supported: boolean;
    strategy: string;
  };
  production_state: "DISABLED" | "LAB" | "CANARY" | "PRODUCTION" | "DEGRADED" | "QUARANTINED";
  last_conformance_test_at?: string | null;
}

export interface ControllerIntent {
  schema_version: "1.0";
  intent_id: string;
  kind: "SUBMIT_PLAN" | "SPAWN" | "RETRY" | "CANCEL" | "REQUEST_REVIEW" | "REQUEST_PR" | "REQUEST_MERGE";
  idempotency_key: string;
  actor: { class: "HUMAN" | "MASTER"; id: string };
  expected_revision: number;
  correlation_id: string;
  causation_id?: string | null;
  payload: Record<string, unknown>;
}

export interface TaskStateEvent {
  schema_version: "1.0";
  event_id: string;
  task_id: string;
  attempt_id: string | null;
  from_state: TaskState;
  to_state: TaskState;
  reason_code: string;
  actor_class: "HUMAN" | "MASTER" | "CONTROLLER" | "WORKER" | "REVIEWER" | "SYSTEM";
  actor_id?: string | null;
  at: string;
  correlation_id: string;
  causation_id?: string | null;
  authoritative_revision?: number;
  details?: Record<string, unknown> | null;
}


export interface SandboxRequest {
  schema_version: "1.0";
  request_id: string;
  task_id: string;
  attempt_id: string;
  machine_id: string;
  tier: SandboxTier;
  run_root: string;
  workspace: {
    source: string;
    mount_path: "/workspace";
    read_only: boolean;
    base_sha: string;
    controller_gid: number;
  };
  image: {
    reference: string;
    digest: string;
  };
  network: {
    profile: "none" | "brokered";
    egress_profile_id: string | null;
    egress_profile_hash: string | null;
    route_id: string | null;
    model: string | null;
  };
  resources: {
    cpu: number;
    memory_bytes: number;
    pids: number;
    tmpfs_bytes: number;
    timeout_seconds: number;
  };
  command: {
    argv: string[];
    env_allowlist: string[];
  };
  policy_hash: string;
  expires_at: string;
  workspace_lease_id: string;
  workspace_lease_hash: string;
}

export interface SandboxAttestation {
  schema_version: "1.0";
  request_id: string;
  task_id: string;
  attempt_id: string;
  machine_id: string;
  status: "PROVISIONED" | "REJECTED" | "FAILED" | "TERMINATED";
  tier: SandboxTier;
  broker: {
    kind: "local-landlock" | "privileged-docker" | "future";
    build: string;
  };
  sandbox: {
    landlock_abi: number | null;
    container_runtime: string | null;
    user_namespace: boolean;
    seccomp: boolean;
    apparmor: boolean;
    cgroups: boolean;
    network_profile: "none" | "brokered";
    network_enforced: boolean;
    remote_git_write_credential_present: false;
    docker_socket_present: false;
    host_home_mounted: false;
    process_uid: number;
    process_gid: number;
    capabilities_dropped: true;
    read_only_rootfs: true;
    no_new_privileges: true;
  };
  egress: {
    profile_id: string;
    profile_hash: string;
    route_id: string;
    model: string;
    gateway_image_digest: string;
    gateway_container_id: string;
    worker_network_id: string;
    gateway_alias: "awf-egress";
    llm_port: number;
    direct_egress_blocked: true;
    provider_secret_in_worker: false;
    attempt_token_scoped: boolean;
  } | null;
  image_digest: string;
  container_id?: string | null;
  started_at: string;
  ended_at?: string | null;
  exit_code?: number | null;
  request_hash: string;
  evidence_hash?: string | null;
  rejection_code?: string | null;
  details?: Record<string, unknown> | null;
}

export interface CandidateDescriptor {
  schema_version: "1.0";
  repo_id: string;
  base_sha: string;
  patch_sha256: string;
  changed_files: string[];
}


export interface QualityProfile {
  schema_version: "1.0";
  profile_id: string;
  revision: number;
  runner: "landlock-local-v1";
  commands: Array<{
    gate: "format" | "lint" | "typecheck" | "build" | "tests" | "secret_scan";
    argv: string[];
    timeout_seconds: number;
  }>;
  scanner_profiles: {
    semgrep: string | null;
    codacy: string | null;
    sonar: string | null;
  };
  network_profile: "none" | "quality-services";
  timeout_seconds: number;
}

export interface ValidationPlan {
  schema_version: "1.0";
  plan_id: string;
  task_id: string;
  candidate_hash: string;
  base_sha: string;
  validation_workspace: string;
  commands: Array<{
    name: string;
    argv: string[];
    required: boolean;
    timeout_seconds: number;
  }>;
  scanner_profiles: {
    semgrep: string | null;
    codacy: string | null;
    sonar: string | null;
  };
  network_profile: "none" | "quality-services";
  timeout_seconds: number;
}

export interface GitIntegrationArtifact {
  schema_version: "1.0";
  strategy: "deterministic-commit-v1";
  task_id: string;
  attempt_id: string;
  repo_id: string;
  base_sha: string;
  candidate_hash: string;
  patch_sha256: string;
  changed_files: string[];
  tree_sha: string;
  commit_sha: string;
  author: {
    name: string;
    email: string;
    timestamp: "2000-01-01T00:00:00Z";
  };
  committer: {
    name: string;
    email: string;
    timestamp: "2000-01-01T00:00:00Z";
  };
  message_sha256: string;
  artifact_hash: string;
}

export interface PostMergeVerificationReport {
  schema_version: "1.0";
  provider: "github";
  task_id: string;
  attempt_id: string;
  repo_id: string;
  merge_receipt_hash: string;
  merge_sha: string;
  required_checks: string[];
  observed_checks: Array<{
    name: string;
    status: "PASS" | "FAIL" | "PENDING" | "ERROR";
    head_sha: string;
  }>;
  status: "PASS" | "PENDING" | "QUALITY_FAILED" | "EXTERNAL_BLOCKER";
  observed_at: string;
  observer: { kind: "trusted-git-integrator"; build: string };
  report_hash: string;
}

export interface GitHubMergeReceipt {
  schema_version: "1.0";
  provider: "github";
  repo_id: string;
  task_id: string;
  attempt_id: string;
  pr_number: number;
  integration_artifact_hash: string;
  remote_verification_report_hash: string;
  expected_head_sha: string;
  merge_method: "squash" | "merge" | "rebase" | "fast-forward";
  merge_sha: string;
  observed_base_sha: string | null;
  base_head_matches_merge: boolean | null;
  merged_at: string;
  observer: {
    kind: "trusted-git-integrator";
    build: string;
  };
  receipt_hash: string;
}

export interface GitHubActionsExecutionReceipt {
  schema_version: "1.0";
  backend: "github-actions";
  task_id: string;
  attempt_id: string;
  machine_id: string;
  worker_repo: string;
  workflow: string;
  dispatch_ref: string;
  workflow_run_id: number;
  run_attempt: number;
  run_url: string;
  runner_environment: "github-hosted";
  status: "completed";
  conclusion: "success";
  started_at: string;
  completed_at: string;
  artifact_id: number;
  artifact_name: string;
  artifact_digest: string;
  workflow_sha: string;
  oidc_sha256: string;
  receipt_hash: string;
}

export interface GitHubPrPublication {
  schema_version: "1.0";
  provider: "github";
  repo_id: string;
  task_id: string;
  attempt_id: string;
  integration_artifact_hash: string;
  branch: string;
  pr_number: number;
  pr_url: string;
  base_ref: string;
  base_sha: string;
  head_sha: string;
}

export interface RemoteVerificationReport {
  schema_version: "1.0";
  provider: "github";
  task_id: string;
  attempt_id: string;
  repo_id: string;
  candidate_hash: string;
  integration_artifact_hash: string;
  expected_base_sha: string;
  expected_commit_sha: string;
  base_ref: string;
  observed_base_sha: string;
  pr_number: number;
  pr_state: "OPEN" | "CLOSED" | "MERGED";
  pr_head_ref: string;
  observed_pr_head_sha: string;
  status: "PASS" | "PENDING" | "BASE_DRIFT" | "HEAD_MISMATCH" | "QUALITY_FAILED" | "EXTERNAL_BLOCKER";
  remote_checks: Array<{
    name: string;
    status: "PASS" | "FAIL" | "PENDING" | "ERROR";
    head_sha: string;
  }>;
  observed_at: string;
  observer: { kind: "trusted-git-integrator"; build: string };
  report_hash: string;
}

export interface VerificationGate {
  status: "PASS" | "FAIL" | "ERROR" | "NOT_APPLICABLE";
  evidence_sha256: string;
  details?: Record<string, unknown> | null;
}

export interface VerificationCommandResult {
  name: string;
  argv: string[];
  exit_code: number;
  duration_ms: number;
  stdout_sha256: string;
  stderr_sha256: string;
}

export interface VerificationReport {
  schema_version: "1.0";
  plan_id: string;
  task_id: string;
  candidate_hash: string;
  base_sha: string;
  status: "PASS" | "FAIL" | "ERROR";
  started_at: string;
  ended_at: string;
  command_results: VerificationCommandResult[];
  gates: Record<string, VerificationGate>;
  verifier: {
    machine_id: string;
    build: string;
  };
  report_hash: string;
}

export interface SandboxWorkspaceLease {
  schema_version: "1.0";
  lease_id: string;
  attempt_id: string;
  machine_id: string;
  controller_uid: number;
  controller_gid: number;
  paths: {
    run_root: string;
    repo: string;
    control: string;
    artifacts: string;
  };
  created_at: string;
  expires_at: string;
  broker_build: string;
  immutable_parent: true;
  lease_hash: string;
}

export interface EgressProfile {
  schema_version: "1.0";
  profile_id: string;
  revision: number;
  gateway_image: { reference: string; digest: string };
  internal_network: {
    gateway_alias: "awf-egress";
    llm_port: number;
    http_proxy_port: number | null;
    direct_egress_denied: true;
  };
  routes: Array<{
    route_id: string;
    provider_id: string;
    protocol:
      | "openai-responses"
      | "openai-chat"
      | "openai-compatible"
      | "openai-compatible-responses"
      | "anthropic"
      | "opencode-free-connect";
    upstream_base_url: string;
    worker_base_path: string;
    worker_auth: {
      kind: "bearer" | "header" | "none";
      header_name: string;
      secret_file: "/run/egress/attempt-token" | null;
    };
    upstream_auth: { kind: "bearer" | "header" | "none"; header_name: string };
    secret_handle: string | null;
    models: string[];
    request_path_prefixes: string[];
  }>;
  package_proxy: {
    enabled: boolean;
    allowed_hosts: string[];
    allowed_ports: number[];
  };
  limits: {
    max_request_bytes: number;
    max_response_bytes: number;
    max_concurrent_requests: number;
  };
  policy_revision: number;
}

# Master → Controller MCP Intent API

The Master receives typed intent/read tools only. It does not receive raw controller shell, unrestricted GitHub mutation, SSH, secret-store, or merge credentials.

## Read tools

### fleet.get_state
Input:
```json
{ "project_id": "string" }
```
Returns compressed authoritative execution state and revision.

### fleet.list_capabilities
Input filters may include repo, risk class and task class.
Returns eligible archetypes, modifiers, machines, harness/model classes — never secrets.

### fleet.get_task
Returns canonical TaskSpec + current task state + attempt lineage.

### fleet.get_attempt
Returns normalized ResultManifest/evidence summary.

### fleet.get_candidate
Returns exact base/candidate identifiers and deterministic gate state.

### repo.get_passport
Returns effective Controller-owned RepoPassport and hash.

### quality.get_gate_status
Returns machine-evaluated gates for an exact candidate hash.

### machine.get_eligibility
Returns eligibility reasons; no arbitrary host shell.

## Intent tools

### fleet.submit_plan
Master submits a DAG proposal. Controller validates:
- project revision
- Repo Passport
- dependency acyclicity
- scope conflicts
- risk/sandbox requirements
- quotas

### fleet.spawn
Input:
```json
{
  "task_spec": { "...": "TaskSpec" },
  "idempotency_key": "string"
}
```
Controller canonicalizes/rejects the TaskSpec before scheduling.

### fleet.retry
Requires task/attempt ID and typed reason. Creates a new attempt; does not rewrite history.

### fleet.cancel
Requests cancellation. Controller checks current state and authority.

### fleet.request_review
Requests independent review for an exact candidate hash.

### repo.request_pr
Requests PR creation after deterministic prerequisites.

### repo.request_merge
This is an intent, never a command. Controller independently checks:
- exact candidate/head SHA
- base drift
- required local/remote CI
- quality gates
- independent review
- protected-path/human requirements
- merge policy

## MCP security invariants

- schemas use closed objects where practical;
- every mutation has idempotency/correlation IDs;
- every response includes authoritative revision/state where relevant;
- secrets are referenced by opaque handles, never returned;
- tool errors are typed and safe to expose to an LLM;
- Controller logs all mutation intents and decisions;
- no generic `exec(command)`, `github.request(...)`, or `secret.get_value(...)` tool is exposed to Master.

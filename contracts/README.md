# Contract Rules

JSON Schema draft: 2020-12.

## Normative contracts

- task-spec.schema.json
- result-manifest.schema.json
- repo-passport.schema.json
- worker-profile.schema.json
- machine-capability.schema.json
- harness-capability.schema.json
- task-state-event.schema.json
- controller-intent.schema.json
- sandbox-request.schema.json
- sandbox-workspace-lease.schema.json
- egress-profile.schema.json
- sandbox-attestation.schema.json
- candidate-descriptor.schema.json
- verification-report.schema.json
- validation-plan.schema.json
- quality-profile.schema.json
- git-integration-artifact.schema.json
- remote-verification-report.schema.json
- github-pr-publication.schema.json
- github-merge-receipt.schema.json
- post-merge-verification-report.schema.json

`types.ts` is non-normative developer convenience.

## Evolution rules

- `schema_version` is mandatory.
- Breaking changes require a new major schema version.
- Controller stores the exact schema/policy/passport revision/hash used by every attempt.
- Historical manifests remain immutable.
- New optional evidence fields may be added compatibly within a major version only when old verifiers fail safely.

## Hash rules

- policy/passport/context/patch/artifact hashes are lowercase SHA-256 hex unless a contract says otherwise.
- Git object identifiers are 40-character SHA-1 in the current Git/GitHub contract surface.
- `SandboxRequest` uses the explicit `awf-sandbox-request-v1` byte-length-prefixed binding implemented identically by TypeScript and Go and checked by `examples/sandbox-request-binding.vector.json`.
- `EgressProfile` uses the explicit `awf-egress-profile-v1` byte-length-prefixed binding implemented identically by TypeScript and Go and checked by `examples/egress-profile-hash.vector.json`.
- Other policy/passport/context/patch/artifact hashes use their contract-specific canonical serialization; callers must not invent ad-hoc JSON serialization.

- github-actions-execution-receipt.schema.json

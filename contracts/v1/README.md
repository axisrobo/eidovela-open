# EIDOVELA v1 Contracts

The `v1` contract line is the **stable** wire contract for EIDOVELA. It is the
default contract line implemented by the core authority and consumed by the
published SDK, CLI and conformance runner.

## Stability guarantees

- The `v1` wire schemas are frozen as published. Additive evolution is allowed
  only when consumers can ignore new fields; removing required fields,
  reinterpreting semantics, narrowing enums or changing serialization requires a
  new contract line (for example `v2`).
- `v1alpha1` remains published for compatibility with earlier consumers but is
  **not** the default line. New consumers should target `v1`.
- Conformance fixtures under `conformance/fixtures` are normative for `v1`
  behavior (PoP binding, workload attestation, lifecycle/revocation SLO,
  exchange, audience binding).

## Contents

Schemas:

- `agent-blueprint.schema.json`
- `agent-identity.schema.json`
- `agent-instance.schema.json`
- `agent-principal.schema.json`
- `authority-binding.schema.json`
- `federation-trust.schema.json`
- `workload-registration.schema.json`

Protocol profiles:

- `enrollment-attestation.md` — optional platform evidence for `complete_enrollment`
- `federation-profile.md` — verified-downstream trust administration and federated introspect
- `revocation-slo.md` — immediate denial after agent revocation
- `token-proof.md` — `private_key_jwt` proof for token issuance

These files are dependency-free from the AGPL core and EE repositories.

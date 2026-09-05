# Contract Governance

Each version directory contains the public schemas and protocol profiles for
that contract line.

- `v1/` — the **stable** contract line. This is the default implemented by the
  core authority and consumed by the published SDK/CLI/conformance runner.
- `v1alpha1/` — the original pre-stable line, kept for compatibility with
  earlier consumers. New consumers should target `v1`.

Contract evolution is additive within a line: fields may be added only when
consumers can ignore them. Removing required fields, reinterpreting semantics,
narrowing enums or changing serialization requires a new contract line.

Core implementation is AGPL and lives in `eidovela`; these contracts remain
Apache-2.0 and dependency-free from core/EE.

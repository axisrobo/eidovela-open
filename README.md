# EIDOVELA Open

## EIDOVELA

**Product:** EIDOVELA solves the core identity plumbing for agent-based systems:
tenant-scoped trust domains, workload attestation with platform recognition
(kubernetes/spiffe/mTLS), private_key_jwt enrollment, and lifecycle-aware token
issuance. It bridges the gap between authentication (who) and authorization
(what/where), providing a verified foundation for federation and console
workflows.

**License:** Apache-2.0 — source available, core AGPL implementation at
https://github.com/axisrobo/eidovela (identity/authentication) + AEGIVELA
(authorization/delegation).

**Module:** `github.com/axisrobo/eidovela-open`

---

## eidovela-open

This repository (`eidovela-open`, Apache-2.0) publishes the public contracts,
SDKs, and client libraries that consume the core EIDOVELA authority.

It includes:

- OIDC discovery and introspection APIs
- SDKs for Agent/workload token exchange
- Protocol conformance (JWT, mTLS, SPIFFE)
- Documentation and examples for the local identity loop

**Public API surface:** introspect, token exchange, federation handoff,
audience-aware verification.

**Docs (Chinese):** <https://github.com/axisrobo/eidovela/blob/main/docs/README.md>

**Topics:** `eidovela` `identity` `authentication` `oidc` `workload-attestation` —
see the [Chinese docs](https://github.com/axisrobo/eidovela/blob/main/docs/README.md)
for full reference.

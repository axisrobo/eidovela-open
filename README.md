# EIDOVELA Open

Public contracts, SDKs, CLI, examples and conformance fixtures for EIDOVELA — the Agent Identity Provider & Authentication Authority.

**Product: EIDOVELA** solves the core identity plumbing for agent-based systems:
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

## About

EIDOVELA (identity/authentication) + AEGIVELA (authorization/delegation) = Agent IAM.
This repository (`eidovela-open`, Apache-2.0) publishes the public contracts,
SDKs, and client libraries that consume the core EIDOVELA authority.

**Public API surface:** introspect, token exchange, federation handoff,
audience-aware verification.

**Docs (Chinese):** <https://github.com/axisrobo/eidovela/blob/main/docs/README.md>

**Topics:** `eidovela` `identity` `authentication` `oidc` `workload-attestation` —
see the [Chinese docs](https://github.com/axisrobo/eidovela/blob/main/docs/README.md)
for full reference.

---

## Contents

- `contracts/` — versioned public contract schemas (v1alpha1)
- `sdk/go` — Go SDK
- `cli/` — command-line tool
- `examples/` — integration examples
- `conformance/` — positive/negative issuer & verifier fixtures

Version format: `major.minor.patch`. Current: 0.1.0.

Distribution governance: `STATUS.md`, `COMPATIBILITY.md` and `contracts/README.md`.

## v0.5 local loop

Start the core daemon, then run the public example:

```text
eidovelad
go run ./examples/local-loop
```

The example registers a Service Agent, registers a workload profile, completes
`private_key_jwt` enrollment, activates the Agent, obtains a short-lived
PoP-bound token, then authoritatively introspects it.

Enrollment supplies workload attributes that must exactly match every selector
on the registered workload profile; callers cannot bypass workload binding by
asserting only an Agent ID.

The Go SDK is available at `sdk/go/eidovela`. It contains the HTTP client,
Ed25519 PoP key generation and offline JWT/JWKS verification. Offline
verification does not check the current lifecycle epoch; high-risk consumers
must use authoritative introspection.

The SDK also supports the initial RFC 8693 token-exchange profile. Exchanged
tokens retain the verified parent identity, PoP key, audience and expiry; the
profile rejects audience widening.

# EIDOVELA Open

[English](README.md) · [简体中文](README.zh-CN.md)

---

## EIDOVELA — the Agent Identity Provider (IdP)

EIDOVELA is a native **Agent Identity Provider (IdP) and authentication authority** for agent-based, private-cloud systems. Unlike a generic OIDC IdP, EIDOVELA is built around what makes *agents* different from human users:

- **Agent lifecycle management** — agents move through Register → Enroll → Activate → Suspend → Revoke, and every issued identity is bound to that lifecycle state.
- **Tenant-scoped trust domains** — only trust domains explicitly provisioned for a tenant (`tenant_trust_domains`) are accepted; workloads cannot attach to a tenant they were never trusted to join.
- **Platform recognition** — workload attestation understands the platform (kubernetes, spiffe, mTLS), so an identity is minted only when the workload's platform attributes match its registered selector.
- **private_key_jwt enrollment** — proof-of-possession enrollment: the agent proves control of its key before a PoP-bound credential is issued.
- **Lifecycle-aware token issuance** — short-lived tokens are bound to the agent's epoch and state; a suspended or revoked agent cannot obtain a valid token.
- **Federation foundation** — operator-configured peer trust anchors
  (`federation-trust` contract + `/v1/federation/trusts` administration) let the
  authoritative introspection endpoint verify and honor tokens issued by a peer
  EIDOVELA issuer for allowed audiences.
- **Instance leases** — a workload instance can be bound to an expiry
  (`instance-lease` profile + `/v1/instances/{id}/lease`); while a lease is set,
  token issuance requires an unexpired lease, so authorization decays with the
  instance lifecycle.
- **Ops projection** — read-only, redacted views for console/ops
  (`ops-projection` profile): agents, instances, evidence, outbox health and
  per-issuer federation status telemetry, all paginated.

### What problem does EIDOVELA solve?

Agent systems have an identity problem generic IdPs do not answer: *"who is allowed to act as this agent, on this platform, inside this tenant?"* EIDOVELA answers it by tightly binding an agent's identity to its lifecycle, its tenant-scoped trust domain, and the platform attestation of the workload that runs it — so authentication ("who") becomes a trustworthy input to authorization ("what/where").

**Identity/authentication = EIDOVELA · Authorization/delegation = AEGIVELA** (Agent IAM).

---

## eidovela-open

This repository (`eidovela-open`, Apache-2.0) is the public, developer-facing distribution for EIDOVELA: versioned public contracts, SDKs, CLI, examples and conformance fixtures that consume the core authority.

Contents:

- `contracts/` — versioned public contract schemas (v1 stable; v1alpha1 retained)
- `sdk/go` — Go SDK (HTTP client, Ed25519 PoP key generation, offline JWT/JWKS verification, RFC 8693 token-exchange profile)
- `cli/` — command-line tool
- `examples/` — integration examples
- `conformance/` — executable threat-scenario fixtures + HTTP runner (`cmd/eidovela-conformance`) driving a live daemon; ships a prebuilt core daemon under `conformance/bin/`

The core server implementation lives in the AGPL repository: <https://github.com/axisrobo/eidovela>

### Public API surface

- Authoritative introspection (audience-aware, incl. federated peer tokens)
- RFC 8693 token exchange (rejects audience widening)
- OIDC discovery & JWKS
- Federation trust administration and verified-downstream introspection
  (`contracts/v1/federation-profile.md`)

---

## Versioning

- Format: `major.minor.patch`
- **`eidovela-open` and `eidovela` (core) share the same version tag** (e.g. `v1.1.0`).
- `eidovela-ee` (enterprise) may carry an independent version/tag.

## Quick start — local loop

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

The Go SDK is available at `sdk/go/eidovela`. Offline verification does not
check the current lifecycle epoch; high-risk consumers must use authoritative
introspection.

---

- License: Apache-2.0
- Module: `github.com/axisrobo/eidovela-open`
- Distribution governance: `STATUS.md`, `COMPATIBILITY.md` and `contracts/README.md`

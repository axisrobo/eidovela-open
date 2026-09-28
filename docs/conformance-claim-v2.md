# EIDOVELA 2.0 Conformance Claim

Status: project implementation claim, not a certification  
Version: 2.2.0  
Date: 2026-09-28

## Scope

EIDOVELA 2.0 implements the Registry Consumer profile against NOMIVELA Agent
Registry contract 1.0 through `github.com/axisrobo/nomivela-open/v2`.

It consumes Registry Context, signed discovery, scoped service principals,
Agent ID, Authority Binding, Workload Registration, Agent Instance or registry
lifecycle records.

## Declared capabilities

| Capability | Claim |
|---|---|
| Registry Context | Atomic context is used for token issuance and authoritative online verification. |
| Lifecycle invalidation | Tokens carry `agent_epoch` and `identity_epoch`; either mismatch invalidates the token online. |
| Enrollment | `private_key_jwt` proof and registered workload selector are required; verified instance is committed to NOMIVELA with a stable idempotency key. |
| Attestation | SPIFFE/mTLS certificate chain and Kubernetes JWT/JWKS verification are available when configured; required trust and platform modes fail closed. Each enrollment records a sanitized attestation result resolvable at `/v1/attestations/{ref}`. |
| Credential generation | Re-enrollment issues a new monotonic generation and revokes prior active generations. |
| PoP | Enrollment and token issuance use Ed25519 proof; identity tokens carry `cnf.jkt`. Introspection accepts an RFC 9449 `dpop_proof` (signature, `htm`/`htu`, time, `ath`, `jti` replay), and `EIDOVELA_REQUIRE_DPOP=1` rejects key-only introspection. |
| Credential lifecycle | Credential generation, revocation and authentication quarantine/disable are enforced during online verification. |
| Discovery | Canonical namespace, signed discovery (when required), registry/JWKS endpoint validation, no-proxy DNS-revalidated retrieval, bounded response and host allowlist checks. |
| Registry service auth | Static or file-reloaded NOMIVELA service-principal bearer token; namespace-scoped `registry.read`, `instance.commit`, and optional `events.consume`. |
| Federation | Active trust, signature, audience, time, PoP and mapping validation; disabling trust invalidates brokered local tokens on their next online verification. Peer JWKS retrieval shares the discovery SSRF/DNS-rebinding controls, and federated evidence namespaces the peer subject as `fed:<issuer>/<subject>` with a correlation id instead of a local agent reference. |
| Event invalidation | Optional cursor replay invalidates bounded Registry caches; authoritative issuance and online verification remain point reads. |
| Security events | Enrollment denials record a bounded reason and challenge correlation id; credential revocation and authentication quarantine/disable/reinstate record sanitized events. No tokens, proofs, evidence or unrestricted attributes are persisted. |

## Proof profiles and artifact versions

| Class | Profile | Notes |
|---|---|---|
| Enrollment proof | Project JWT proof, `aud=eidovela:enroll`, challenge-bound `jti`/`nonce` | Not an RFC 7523 `private_key_jwt` wire binding |
| Workload evidence | `private_key_jwt`, `spiffe_svid`, `k8s_projected_sa`, `mtls` | Versioned through NOMIVELA `proofRequirements` when present |
| Identity token | Ed25519 `EdDSA`, `cnf.jkt` (RFC 7638), `agent_epoch` + `identity_epoch`, audience-bound | TTL 10 minutes |
| Request PoP | RFC 9449 DPoP on introspection (`htm`/`htu`/`ath`/`jti`) | Optional; mandatory with `EIDOVELA_REQUIRE_DPOP=1` |
| Registry contract | NOMIVELA `agent-registry-v1.0` via `nomivela-open/v2` | Registry Context, idempotent commit, signed discovery, event cursor |
| Public contracts | `contracts/v2` (Registry Consumer), `contracts/v1` (frozen) | — |

## Bounds

| Bound | Value |
|---|---|
| Registry read cache TTL | `2s` default; `EIDOVELA_NOMIVELA_CACHE_TTL=0s` disables |
| Identity token TTL | 10 minutes |
| DPoP proof max age | 1 minute, plus 30s forward skew |
| Enrollment challenge TTL | 5 minutes |
| Discovery/JWKS response cap | 64 KiB discovery, 256 KiB peer JWKS |
| Registry JWKS/discovery key cache | 5 minute TTL, 30 second bounded unknown-`kid` refresh |

## Revocation SLO

- Registry suspension/retirement, identity suspension/revocation, or instance
  termination/expiry invalidates an unexpired token on its next authoritative
  online verification.
- Credential revocation and authentication quarantine/disable block issuance and
  fail online verification immediately.
- Disabling a federation trust revokes an unexpired brokered token on its next
  online verification.
- Offline verification is deliberately local and does not enforce revocation.

## Unmet clauses

- A real NOMIVELA 2.0 deployment is exercised by the opt-in integration test and
  by the core CI `real-registry` job, which starts NOMIVELA against PostgreSQL
  with a scoped service principal. A production deployment must still validate
  its own signing keys, migrations and principal policy.
- Workload attestation trust and platform evidence are opt-in unless the
  conforming production profile settings are configured.
- HSM/KMS custody, multi-region operation and console administration are
  enterprise (EE) capabilities outside this claim.

## Verification

The released source passes:

```text
# eidovela/backend
go build ./...
go vet ./...
go test ./...

# eidovela-open
go build ./...
go test ./conformance/...
```

The public conformance runner starts a consumer-mode EIDOVELA daemon with an
in-process NOMIVELA test double. Production integration must additionally test
the organization’s real NOMIVELA service-principal policy, signing key/trust
anchor distribution and database migration procedure.

## Required deployment configuration

- `EIDOVELA_NOMIVELA_NAMESPACE`
- Either `EIDOVELA_NOMIVELA_URL` or `EIDOVELA_NOMIVELA_DISCOVERY_URL`
- For protected Registry deployments: `EIDOVELA_NOMIVELA_TOKEN` or
  `EIDOVELA_NOMIVELA_TOKEN_FILE`
- `EIDOVELA_NOMIVELA_DISCOVERY_REQUIRE_SIGNATURE=true` when the deployment
  requires signed discovery, plus trusted discovery keys or Registry JWKS
  resolution as configured
- `EIDOVELA_ATTESTATION_REQUIRE_TRUST=1` and
  `EIDOVELA_ATTESTATION_REQUIRE_PLATFORM=1` for the conforming production
  workload-attestation profile

## Reproducible execution

The public conformance suite runs in CI (`.github/workflows/ci.yml`): it checks
out this repository, builds the core daemon from `axisrobo/eidovela`, starts the
in-process NOMIVELA test double, and runs the fixtures with `-count=1`. The
fixtures, the daemon and the fake registry double are all committed, so the
result is reproducible.

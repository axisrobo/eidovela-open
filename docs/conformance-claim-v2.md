# EIDOVELA 2.0 Conformance Claim

Status: project implementation claim, not a certification  
Version: 2.0.0  
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
| Attestation | SPIFFE/mTLS certificate chain and Kubernetes JWT/JWKS verification are available when configured; required trust mode fails closed. |
| PoP | Enrollment and token issuance use Ed25519 proof; identity tokens carry `cnf.jkt`. |
| Credential lifecycle | Credential generation, revocation and authentication quarantine/disable are enforced during online verification. |
| Discovery | Canonical namespace, signed discovery (when required), registry/JWKS endpoint validation, no-proxy DNS-revalidated retrieval, bounded response and host allowlist checks. |
| Registry service auth | Static or file-reloaded NOMIVELA service-principal bearer token; namespace-scoped `registry.read`, `instance.commit`, and optional `events.consume`. |
| Federation | Active trust, signature, audience, time, PoP and mapping validation; disabling trust invalidates brokered local tokens on their next online verification. |
| Event invalidation | Optional cursor replay invalidates bounded Registry caches; authoritative issuance and online verification remain point reads. |

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

## Known limitations

- The public conformance runner uses a fake Registry; it does not replace an
  end-to-end run against a production NOMIVELA 2.0 deployment.
- Workload attestation trust is opt-in unless
  `EIDOVELA_ATTESTATION_REQUIRE_TRUST=1` is configured.
- HSM/KMS custody, multi-region operation and console administration remain
  enterprise capabilities.

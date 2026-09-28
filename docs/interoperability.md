# Agent IAM Series Interoperability

This document explains how an independent Agent IAM implementer can run the
EIDOVELA conformance suite, which parts of the Agent IAM Series it exercises,
and what a passing run does and does not prove.

## Artifact and profile versions

| Item | Version |
|---|---|
| EIDOVELA | 2.2.0 |
| Public contracts | `contracts/v2` (Registry Consumer); `contracts/v1` frozen |
| NOMIVELA Agent Registry contract | `agent-registry-v1.0` |
| NOMIVELA SDK | `github.com/axisrobo/nomivela-open/v2` |

## Coverage by Agent IAM Series part

The fixture manifest (`conformance/fixtures/manifest.json`) maps every fixture to
a part, threat reference and expected outcome.

| Part | Fixtures | Count |
|---|---|---|
| Part 2 — Registry consumption | `P-O1-1`, `P-O4-1`, `P-O5-1` | 3 |
| Part 3 — Attestation and authentication closure | `P-T1-1`, `P-T2-1/2/3`, `P-T7-1`, `P-I1-1`, `P-O3-1`, `P-O8-1`, `N-T1-1`, `N-T2-4/5/6`, `N-T4-1/2`, `N-T7-1`, `N-T8-1`, `N-I1-1/2` | 18 |
| Part 5 — Federation and brokered identity | `P-F1-1`, `P-BR-1`, `N-F1-1..6`, `N-BR-1` | 9 |

Threat references follow the fixture `threat_ref`: `T1` PoP binding, `T2`
workload attestation, `T4` lifecycle/revocation, `T7` exchange, `T8` audience
binding, `I1` instance state, `F1` federation, `BR` broker issuance, `O*`
registry read projections.

## Running the suite

The runner starts a consumer-mode EIDOVELA daemon and an in-process NOMIVELA
test double; no external deployment is required.

```text
go run ./cmd/eidovela-conformance
go run ./cmd/eidovela-conformance -run T2-
go run ./cmd/eidovela-conformance -run F1-
```

CI runs the same suite on `main` and on pull requests by building the core
daemon from `axisrobo/eidovela` (see `.github/workflows/ci.yml`).

### Against a real Registry

The core repository ships an opt-in integration test that provisions a real
NOMIVELA 2.0 deployment:

```text
EIDOVELA_TEST_NOMIVELA_URL=http://127.0.0.1:8090
EIDOVELA_TEST_NOMIVELA_NAMESPACE=https://registry.internal.example/namespaces/acme
EIDOVELA_TEST_NOMIVELA_TOKEN=<service principal with registry.write, registry.read, instance.commit>
```

## What a passing run proves

- A registry-authorized Agent, Agent ID, Workload Registration and Instance are
  required before any token is issued.
- `private_key_jwt` possession and the registered workload selector are enforced,
  and platform evidence is verified or refused when the profile requires it.
- Identity tokens carry `agent_epoch` and `identity_epoch`, and a registry
  suspension/revocation or instance termination invalidates an unexpired token
  online.
- Enrollment proof replay, wrong proof keys, selector mismatches, audience
  widening and cross-audience introspection are rejected.
- Federation requires an active trust, a known `kid`, a valid signature,
  audience, time and PoP; disabling a trust revokes a brokered local token.
- Denied and administrative paths emit sanitized security events.

## What a passing run does not prove

- It is not a certification and does not replace a deployment-specific security
  review.
- The default run uses a fake Registry; the opt-in integration test and the core
  CI `real-registry` job cover the real one.
- Workload attestation trust and platform evidence are opt-in unless the
  conforming production profile settings are enabled.
- HSM/KMS custody, multi-region operation and console administration are
  enterprise capabilities outside this repository.

## Implementing the suite yourself

An independent implementation can reuse the fixtures by providing an HTTP
endpoint compatible with the EIDOVELA consumer-mode contract
(`contracts/v2`): enrollment, token issuance, introspection, registry read
views, verified agent context, and the authentication-state and credential
lifecycle endpoints. The fixture schema
(`conformance/fixtures/fixture.schema.json`) documents each step operation.

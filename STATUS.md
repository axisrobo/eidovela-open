# EIDOVELA Status

**Version:** 2.2.1 | **Contract line:** v2 (Registry Consumer); v1 frozen

This repository (`eidovela-open`, Apache-2.0) publishes released public
contracts, SDKs, CLI, examples, conformance and distribution status. The
product spans three repositories; their implemented capabilities and status are
summarized below. Internal EE planning remains in the private EE repository.

| Repository | License | Version |
|---|---|---|
| `eidovela` (core) | AGPL-3.0-or-later | shared with open (`2.2.1`) |
| `eidovela-open` (this repo) | Apache-2.0 | shared with core (`2.2.1`) |
| `eidovela-ee` (enterprise) | AxisRobo Enterprise License | independent (`0.6.0`) |

## Core — `eidovela` (AGPL-3.0-or-later)

The authentication authority. Registry-consumer mode is the only runtime mode:
Agent, Agent ID, Authority Binding, Workload Registration and Agent Instance are
read from the NOMIVELA Agent Registry; EIDOVELA authors none of them and fails
closed when NOMIVELA is unavailable.

Implemented:

- **Registry consumer (v2.0)** — atomic Registry Context read for issuance and
  online verification; write endpoints return `410 write_authority_moved`; the
  legacy local registry is removed; a short-lived positive cache is invalidated
  from the NOMIVELA change stream while issuance/verification keep the
  authoritative point read.
- **Discovery (R2)** — signed `/.well-known/agent-iam` resolution with canonical
  namespace matching, exact issuer checks, and SSRF/DNS-rebinding controls.
- **Enrollment** — `private_key_jwt` proof of possession with workload
  attestation (SPIFFE X.509/JWT-SVID, Kubernetes projected ServiceAccount, mTLS),
  registered-selector matching, replay protection, and idempotent instance
  commit to NOMIVELA.
- **STS / tokens** — OIDC discovery, JWKS, short-lived Ed25519 PoP tokens
  carrying dual `agent_epoch`/`identity_epoch` (either change invalidates the
  token online), authoritative introspection with RFC 9449 DPoP, and a bounded
  RFC 8693 token exchange that rejects widening.
- **Credential lifecycle** — monotonic credential generations, revocation, and
  authentication quarantine/disable/reinstate enforced during online
  verification.
- **Federation** — peer trust administration, verified-downstream introspection,
  brokered issuance (`POST /v1/broker/issue`), and trust-disable that revokes a
  brokered local token before expiry.
- **Attestation** — sanitized attestation results resolvable at
  `/v1/attestations/{ref}`.
- **Evidence / outbox** — sanitized enrollment-denial and administration events,
  PostgreSQL stores and a leased, durable outbox (DLQ admin read/redrive).
- **Ops projection** — agents (list/detail), instances, evidence (`since`,
  `event_type`), outbox health, counters and federation telemetry; blueprint
  state machine.
- **Key provider seam** — the public `provider.KeyProvider` boundary; the
  reference in-memory provider plus the public `registryclient` package and
  `server.RegistryFromEnv`/`server.AttestationFromEnv` helpers.

Verification: `go build/vet/test ./...` green in `backend/`.

## Open — `eidovela-open` (Apache-2.0, this repository)

The developer-facing distribution.

- `contracts/` — public contract schemas: `v2` (Registry Consumer, default),
  `v1` (frozen), `v1alpha1` (retained).
- `sdk/go` — Go SDK: HTTP client, Ed25519 PoP key generation, offline JWT/JWKS
  verification, RFC 8693 token-exchange profile.
- `cli/`, `examples/` — command-line tool and integration examples.
- `conformance/` — executable threat-scenario fixtures and the HTTP runner
  (`cmd/eidovela-conformance`) driving a consumer-mode daemon against an
  in-process NOMIVELA test double.
- `docs/conformance-claim-v2.md` — the EIDOVELA 2.0 implementation claim and
  deployment prerequisites.
- `docs/interoperability.md` — how to run the fixtures and the Agent IAM Series
  parts they cover.

The prebuilt core daemon is **not** committed; the conformance scripts and CI
build it on demand.

## Enterprise — `eidovela-ee` (proprietary, independent version `0.6.0`)

Enterprise infrastructure layered on the open core; it never replaces open
capabilities.

- **`eidovelad-ee`** — the authority daemon in NOMIVELA registry-consumer mode
  (through the shared `server.RegistryFromEnv`/`server.AttestationFromEnv`
  helpers), with EE signing-key providers.
- **Key custody** — `EIDOVELA_KEY_PROVIDER` selects `memory`, `openbao` (OpenBao
  Transit remote signing: keys never leave OpenBao, no cgo, private-CA trust,
  mTLS client certificates, rotation grace persisted across restarts) or
  `pkcs11` (direct hardware custody; cgo). Every provider passes the shared
  `keyprovider/conformance` contract.
- **Broker** — SPIFFE X.509-SVID inbound adapter with strict bundle-chain
  validation and fail-closed registry resolution; brokered-issuance end-to-end.
- **Console / ops** — `eidovela-console` CLI (agents, evidence, outbox/redrive,
  federation trust, key custody) and the `consoleops` read aggregator over the
  public ops surface.
- **Advanced federation and tenancy** — Entra/AD FS/Keycloak bridge designs,
  CAEP/SSF, tenant region affinity and per-tenant IdP configuration.

Pending: PKCS#11 cgo wiring (verifiable on the SoftHSM CI host) and the console
web UI.

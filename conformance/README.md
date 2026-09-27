# EIDOVELA Conformance

Executable threat-scenario fixtures that drive a live `eidovelad` over HTTP and
assert `allow`/`deny` per the EIDOVELA contract.

## Registry separation

Agent, Agent ID, Authority Binding, Workload Registration and Agent Instance
authority belongs to the NOMIVELA Agent Registry, and `eidovelad` serves its
retired registry authoring endpoints with `410 write_authority_moved`.

The runner therefore starts an **in-process fake NOMIVELA registry**
(`runner.FakeRegistry`) alongside a consumer-mode daemon and passes it via
`EIDOVELA_NOMIVELA_URL`/`EIDOVELA_NOMIVELA_NAMESPACE`. Fixtures seed Agent,
Agent ID, Workload Registration and instance state through the fake registry
rather than authoring records through the daemon, and registry lifecycle ops
(`suspend`, `revoke`, `suspend_identity`, `instance_terminate`) mutate the fake.
Registry read caching is disabled for the suite so a lifecycle change is
observed immediately.

Fixtures are self-contained per scenario: `eidovelad` restarts nothing, but each
scenario seeds a fresh Agent ID in the fake registry.

## Layout

- `fixtures/` — runnable scenarios (`P-*` positive, `N-*` negative). Each file
  is an ordered scenario: seed a workload, complete enrollment (with synthesized
  private_key_jwt / spiffe_svid / k8s_projected_sa / mtls evidence), drive
  registry lifecycle, issue/exchange tokens, introspect, and (for federation)
  register peer trusts and introspect peer-signed tokens.
- `fixtures/fixture.schema.json` — JSON schema for a scenario.
- `fixtures-internal/` — verifier/issuer-internal semantics that are **not**
  observable through the public HTTP surface (unknown-issuer crafting, tenant
  override, retired-signing-key rotation). These are pinned by core unit tests
  (`internal/sts`, `internal/registryclient`) instead.
- `runner/` — Go library that executes fixtures against a daemon plus the fake
  registry.

## Prerequisites

A consumer-mode `eidovelad` binary under `conformance/bin` (built by CI or
locally). The runner starts the daemon and the fake registry itself; no external
NOMIVELA deployment is required. The daemon binary must be current with the core
registry-consumer code:

```text
# from eidovela/backend
go build -o ../eidovela-open/conformance/bin/eidovelad ./cmd/eidovelad
```

The runner only talks HTTP and depends only on the Go SDK (no AGPL core import),
so it stays within the Apache-2.0 dependency boundary.

## Run

```text
go run ./cmd/eidovela-conformance
```

Filter to one fixture family:

```text
go run ./cmd/eidovela-conformance -run T2-
go run ./cmd/eidovela-conformance -run O-
```

## Evidence synthesis

For attested enrollment the runner synthesizes real evidence:

- `private_key_jwt` — PoP proof over the agent enrollment challenge.
- `spiffe_svid` — a self-signed leaf certificate carrying the requested
  `spiffe://` URI SAN.
- `mtls` — a self-signed client-auth certificate with the requested CN/DNS.
- `k8s_projected_sa` — a projected-token-shaped JWT carrying the requested
  `iss`/`sub`.

The daemon's attestation layer checks this evidence against the registered
workload selector and trust domain; the runner does not fabricate registry
state.

For federation scenarios the runner also starts an in-process **peer issuer**
that serves a loopback `jwks.json` and signs peer tokens. `register_federation_trust`
points the trust's `jwks_uri` at that peer, so the daemon really fetches and
verifies against a live JWKS. The peer requires the daemon to reach `127.0.0.1`,
so remote daemons (`-server` to another host) cannot run `F*` fixtures.

## Coverage

| Family | Covered | Notes |
|---|---|---|
| T1 PoP binding | N-T1-1, P-T1-1 | wrong-key introspect inactive; valid twin active |
| T2 workload attestation | N-T2-4/5/6, P-T2-1/2/3 | spiffe trust-domain, k8s SA, mTLS selector |
| T4 lifecycle / revocation | N-T4-1/2 | stale registry epoch + revocation SLO after registry suspend/revoke |
| T7 exchange | N-T7-1, P-T7-1 | audience widening denied; same-audience child active |
| T8 audience binding | N-T8-1 | token inactive under a different introspect audience |
| F1 federation | P-F1-1, N-F1-1..6 | trusted peer active; unknown issuer, disabled trust, non-allowed audience, expired token, unmapped agent claim, PoP mismatch all deny |
| I1 instance lease | P-I1-1, N-I1-1 | leased instance issues active tokens; a terminated registry instance cannot be leased again or issue |
| O1 registry views | P-O1-1, P-O3-1, P-O4-1 | registry agent view, verified agent context and since-filtered evidence expose the scenario |
| O5 instance view | P-O5-1 | the registry instance view reports a fresh lease as tokenable |
| O8 outbox rows | P-O8-1 | the per-row outbox projection exposes the enrollment entry as pending for DLQ review |
| BR broker issuance | P-BR-1, N-BR-1 | a verified peer assertion imports as a local PoP-bound token (active under its bound key only); an untrusted issuer cannot be imported |

Retired with the registry authority: blueprint lifecycle (`B1`), agent-registry
cursor pagination (`O7`), suspend-with-reason (`O6`) and agent-registry
pagination guards (`O1`/`O2`), because their endpoints no longer exist.

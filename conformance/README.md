# EIDOVELA Conformance

Executable threat-scenario fixtures that drive a live `eidovelad` over HTTP and
assert `allow`/`deny` per the EIDOVELA contract.

## Layout

- `fixtures/` — runnable scenarios (`P-*` positive, `N-*` negative). Each file
  is an ordered scenario: register an agent + workload, complete enrollment
  (with synthesized private_key_jwt / spiffe_svid / k8s_projected_sa / mtls
  evidence), drive lifecycle, issue/exchange tokens, introspect, and (for
  federation) register peer trusts and introspect peer-signed tokens.
- `fixtures/fixture.schema.json` — JSON schema for a scenario.
- `fixtures-internal/` — verifier/issuer-internal semantics that are **not**
  observable through the public HTTP surface (unknown-issuer crafting, tenant
  override, retired-signing-key rotation). These are pinned by core unit tests
  (`internal/sts` issuer_test.go, registry tests) instead.
- `runner/` — Go library that executes fixtures against a daemon.

## Prerequisites

A running EIDOVELA daemon. In-memory mode is sufficient:

```text
# from eidovela/backend
EIDOVELA_LISTEN_ADDR=127.0.0.1:8099 EIDOVELA_ISSUER=https://eidovela.example.test \
  go run ./cmd/eidovelad
```

The runner only talks HTTP and depends only on the Go SDK (no AGPL core import),
so it stays within the Apache-2.0 dependency boundary.

## Run

```text
go run ./cmd/eidovela-conformance -server http://127.0.0.1:8099
```

Filter to one fixture family:

```text
go run ./cmd/eidovela-conformance -server http://127.0.0.1:8099 -run T2-
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
| T4 lifecycle / revocation | N-T4-1/2 | stale epoch + revocation SLO after suspend/revoke |
| T7 exchange | N-T7-1, P-T7-1 | audience widening denied; same-audience child active |
| T8 audience binding | N-T8-1 | token inactive under a different introspect audience |
| F1 federation | P-F1-1, N-F1-1..6 | trusted peer active; unknown issuer, disabled trust, non-allowed audience, expired token, unmapped agent claim, PoP mismatch all deny |
| I1 instance lease | P-I1-1, N-I1-1 | leased instance issues active tokens; terminated instance cannot lease again or issue |
| O1 ops projection | P-O1-1 | read projections expose the agent, its evidence and outbox health |

# Consuming EIDOVELA: FP-1 integration guide for PRAXOVELA and LIMENORA

This guide is for the consumer repositories that present an EIDOVELA-issued,
PoP-bound token through a gateway:

- **PRAXOVELA** (`packages/adapters/eidovela/...`) — the agent host / HTTP client.
- **LIMENORA** (`backend/go/...`) — the gateway that mediates the resource call.

It describes how to depend on the EIDOVELA v3 SDK and how each side implements the
candidate FP-1 presentation profile. It is a guide, not an implementation claim;
the normative wire contract is
[`contracts/v3.0/federated-presentation.md`](../contracts/v3.0/federated-presentation.md)
and the response schema
[`contracts/v3.0/token-context-introspection.schema.json`](../contracts/v3.0/token-context-introspection.schema.json).

## Dependency

Both consumers are Go modules. Depend on the lowerCamelCase client (not the
frozen v2 package):

```text
require github.com/axisvela/eidovela-open v0.0.0

// local sibling checkout; publish to a tagged module for release
replace github.com/axisvela/eidovela-open => ../../../EIDOVELA-open
```

Import path: `github.com/axisvela/eidovela-open/sdk/go/eidovela/v3`.

## What the SDK provides

| Need | SDK call |
| --- | --- |
| Enroll the workload | `CreateChallenge`, `CompleteEnrollment`/`CompleteEnrollmentWithAttestation` |
| Get a PoP token | `Token` (agentId/instanceId/audience + private key) |
| Verify locally | `Verify` (signature, audience, expiry, `cnf.jkt`, dual epoch) |
| Sign a request proof | `SignDPoP(key, method, target, token, iat)` |
| Introspect with context | `IntrospectContext(token, audience, proof, presenterPub)` |
| Context type | `TokenContext` |
| Key thumbprint | `Thumbprint`, `JWKFromPublic` |
| Broker import | `BrokerIssue` |
| Registry reads | `VerifiedContext`, `ListRegistryAgents`, `ListRegistryInstances` |
| Federation | `CreateFederationTrust`, `FederationTrusts`, `SetFederationTrustStatus` |

Do not hand-roll the wire: the SDK emits the exact camelCase fields the daemon
expects (`agentId`, `publicKey`, `proofJwt`, `enrollmentId`, `dpopProof`,
`includeContext`, ...).

## Two proofs, two verifiers

The workload signs **two** RFC 9449 proofs with the same Ed25519 key bound in the
token `cnf.jkt`:

- **Resource proof** — bound to the outbound resource request; verified by
  LIMENORA.
- **Introspection proof** — bound to `POST {EIDOVELA BaseIssuer}/v1/introspect`;
  relayed unchanged by LIMENORA and verified by EIDOVELA.

Both `ath` are the SHA-256 of the same exact token; the two proofs use distinct
single-use `jti`. A proof must never be retargeted or reused for the other role,
and the private key never leaves PRAXOVELA.

## PRAXOVELA — client tasks

1. **DPoP signer.** Use `v3.SignDPoP` (module `sdk/go/eidovela/v3`); it produces
   `typ: dpop+jwt`, `alg: EdDSA`, the public `jwk`, and `htm/htu/ath/iat/jti`.
   The existing adapter signer (`packages/adapters/eidovela/pop.go`) emits
   `typ: JWT` and cannot be reused as-is.
2. **Resource proof.** Per the configured `resource_proof_carriage`:
   - `request_header` (default): bind the intercepted inner request's exact
     method and `scheme://host/path`.
   - `connect_header`: bind the CONNECT authority `scheme://host:port`.
3. **Introspection proof.** Bind `POST {EIDOVELA BaseIssuer}/v1/introspect` and
   hand it to LIMENORA for relay (or call introspection directly where the
   topology allows).
4. **Key custody.** Sign locally; send only the proof and public JWK.
5. **Fail closed.** If signing fails, fail the egress; never fall back to a
   plaintext or key-only path.
6. **Existing adapter.** `Introspect` currently sends only `publicKey`
   (`packages/adapters/eidovela/client.go`, `wire.go`); migrate it to the v3 SDK
   or add `dpopProof`/`includeContext`.

## LIMENORA — gateway tasks

1. **Configuration** (`backend/go/internal/command/{run.go,config.go}`): add
   `resource_proof_carriage`, `agent_tunnel_policy`, `resource_proof_header`,
   `resource_proof_scheme`, `eidovela_url`, `eidovela_audience`, with per-route
   overrides. Validate at startup; refuse invalid combinations (for example
   `authority_binding` without `connect_header`).
2. **Resource proof verification** (`backend/go/internal/gateway/`):
   - Extract the proof from the configured location (MITM inner header, or
     CONNECT header).
   - Derive the expected target from **trusted routing**, never from
     `Forwarded`/`X-Forwarded-*`.
   - Apply the normative `htu-normalization.v1` comparison, verify the signature,
     check `ath` = SHA-256 of the exact token, enforce freshness, and consume the
     `jti` in a shared replay store.
3. **Introspection** (new EIDOVELA client; none exists today): call
   `POST /v1/introspect` with `{token, audience, dpopProof, includeContext:true}`
   over TLS with bounded timeout/size and no redirects. Prefer
   `v3.IntrospectContext`, then enforce `tokenHash`, `presenterJkt` (equal to the
   resource-proof key), issuer, namespace, audience, and `identityType`/
   `subjectRef`.
4. **Binding dispatch** (`backend/go/internal/agentbinding/contracts.go`,
   `backend/go/internal/store/postgres/policy_resolver.go` `resolveConnectAgent`):
   assemble a `Binding` (agentRef, agentClass, identityType, namespace, agentId,
   both epochs, subjectRef) and feed `identity_mode=federated`. Required fields
   missing ⇒ deny.
5. **Tunnel policy** (`backend/go/internal/gateway/connect.go` `decideConnect`):
   when agent processing is selected and proof is required, default `deny` for an
   un-intercepted raw tunnel; allow authority binding only when configured. A
   presented agent credential is never `NotApplicable`, never downgraded to
   native/application auth.
6. **Secret hygiene.** Strip proof headers before forwarding upstream; never log
   or store tokens/proofs/private material.

## Failure semantics (both sides)

- Consumer-side failures deny; they never downgrade.
- Provider outage, replay-store failure, or missing context ⇒ deny.
- Missing registry identity attributes (`identityType`, `subjectRef`) ⇒ deny, not
  inferred from class or caller input.
- `disabled` / key-only is never a fallback after a configured verifier fails.

## Testing today (LIMENORA unblocked)

LIMENORA can be implemented and tested before PRAXOVELA is ready:

- Generate test proofs with `v3.SignDPoP` (this SDK) — the same generator used by
  the Open conformance fixtures.
- Run a real EIDOVELA daemon (consumer mode) and exercise
  `v3.IntrospectContext` end to end.
- Reuse the Open provider fixtures
  ([`conformance/presentation/`](../conformance/presentation)) for positive/negative
  provider cases; extend them for the gateway resource-proof path once LIMENORA
  exists.

## Out of scope (this profile)

Peer/brokered identity context over the context API, HTTPS CONNECT without
interception (unless the operator explicitly opts into `authority_binding`),
resource query/body integrity, and token exchange at the proxy. See the contract
for the full non-goals.

## References

- Candidate contract: [`contracts/v3.0/federated-presentation.md`](../contracts/v3.0/federated-presentation.md)
- Context schema: [`contracts/v3.0/token-context-introspection.schema.json`](../contracts/v3.0/token-context-introspection.schema.json)
- v3 SDK: [`sdk/go/eidovela/v3`](../sdk/go/eidovela/v3)
- Provider fixtures: [`conformance/presentation`](../conformance/presentation)
- EIDOVELA-owned gate/plan (core repo): `docs/rfcs/federated-presentation-gate.md`,
  `docs/planning/federated-presentation-plan.md`

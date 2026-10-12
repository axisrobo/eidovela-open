# Federated Presentation Candidate FP-1

Status: candidate, 2026-10-12. The user selected separate client-signed proofs
and gateway resource verification. Core/Open provider work does not constitute
PRAXOVELA/LIMENORA owner review or end-to-end production acceptance.

## Scope

This initial profile supports locally issued EIDOVELA registry-bound tokens
presented through an inspecting HTTP gateway. Peer and brokered identity context,
opaque HTTPS CONNECT tunnels, resource-query/body integrity, and token exchange
at the proxy are not supported by this candidate. Routes requiring those
guarantees MUST NOT claim FP-1 conformance. Existing application authentication
must not be replaced by optional agent processing.

## Separate Proofs

The workload signs two RFC 9449 proofs using the same Ed25519 key bound in the
token's `cnf.jkt`. Each has a random, distinct, single-use `jti`, `iat`, `ath`, and
protected header `typ: dpop+jwt`, `alg: EdDSA`, public `jwk`.

- Resource proof: exact resource HTTP method and externally configured absolute
  resource URI. LIMENORA derives the expected target from trusted routing, not
  caller forwarding headers, validates the key/token binding and consumes replay.
- Introspection proof: exact `POST` and `{configured EIDOVELA BaseIssuer}/v1/introspect`.
  LIMENORA relays this proof unchanged; EIDOVELA validates it and consumes replay.

Both `ath` values are unpadded base64url SHA-256 of the same exact token bytes.
Both presenter keys must match that token and each other. No retargeting,
proxy-signed replacement, private-key transfer, or token substitution is allowed.
The resource proof MUST NOT be submitted as the introspection proof.

Target comparison ignores scheme/host case but preserves escaped path case and
trailing slashes. Query/fragment are excluded under RFC 9449; no default-port,
percent-escape, dot-segment, or routing-rewrite equivalence is assumed. Resource
semantics that depend on unsigned query/body need a separately approved binding.
Proof age is strictly below 60 seconds; future skew is at most 30 seconds.
Replay is atomic across replicas, deployment-scoped, retained through the entire
acceptance window, and fails closed on storage failure. EIDOVELA's current ledger
scope is deployment plus `dpop:` plus `jti`; gateways maintain their own domain.
Neither store may silently switch to per-process memory in production.

Proofs are consumed before downstream token/policy decisions. Every retry uses
new proofs; retries never duplicate an already dispatched operation. An invalid
or unavailable agent provider MUST NOT trigger native/application fallback.

## Token-Bound Context API

Additive opt-in request to existing `POST /v1/introspect`:

```json
{
  "token": "<exact token>",
  "audience": "<operator-configured resource audience>",
  "dpopProof": "<client-signed introspection proof>",
  "includeContext": true
}
```

`includeContext: true` ALWAYS requires DPoP, even when legacy optional-proof mode
is configured. `publicKey` alone cannot satisfy it. No resource method/URI or
caller Agent ID is accepted as authoritative input. The complete response is
described by `token-context-introspection.schema.json`.

An active response contains a context with schemaVersion
`eidovela.token-context.v1`, namespace, agentId, agentRef, normalized agentClass,
raw registryClass, identityType, subjectRef when required, both epochs,
instanceId, issuer, audience, expiresAt, tokenHash, and presenterJkt.
EIDOVELA derives identity from the verified token and reuses the exact atomic
Registry Context snapshot used for online verification. It checks authentication
state, credential status, instance state/lease, and both epochs. Token namespace
must match the registry namespace and server deployment scope must match.

Missing required attributes deny instead of being inferred. `interactive` and
`digitalEmployee` require nonblank subjectRef; `autonomous` forbids subjectRef.
The current context profile supports normalized `twin`, `service`, `ephemeral`;
raw registryClass remains separate. Registry identity data requires NOMIVELA SDK
v2.1.0 or later; older records without identityType fail context verification.

Denial returns `200 {"active":false}` with no context. Malformed/missing/replayed
proof returns 401 (invalid input may return 400). Unsupported peer/brokered
context also returns inactive; this is not evidence that a peer token is globally
invalid. Consumers reject any non-200, missing context, or active:false without
downgrade. Responses use `Cache-Control: no-store`.

Omitting includeContext preserves the existing active-only response semantics.
GET `/v1/verified-agent-context` remains a registry lookup, not this proof-bound
API. No identityType is added to existing token claims by this candidate.

## Consumer Requirements

LIMENORA must validate issuer, audience and namespace against operator-selected
route policy, tokenHash against the exact presented token, and presenterJkt
against the resource-proof key. It accepts complete context only on the same
introspection exchange and must not cache it as a substitute for online checks.
The context is an authenticated TLS response, not a signed portable grant.
Authorization/delegation remains AEGIVELA-owned; registry type and subject do not
implicitly grant authority. No complete token/proof may enter logs or evidence.

Provider transport uses operator-controlled TLS endpoints, bounded timeouts and
response sizes, rejects redirects, and has no credential-bearing errors.
The new Go SDK method bounds transport without changing frozen legacy methods.

## Remaining Freeze and Release Gates

PRAXOVELA/LIMENORA must agree resource-proof transport, trusted target derivation
for their concrete proxy stack, and authorization dispatch/retry behavior. This
document deliberately does not invent a gateway header consumed by nonexistent
code. Until those agreements and FP-01 through FP-12 real-component tests exist,
federated production remains blocked. Local Core HTTP tests and Open SDK tests
are provider evidence only, not a complete federated presentation claim.

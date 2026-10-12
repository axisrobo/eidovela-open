# Federated Presentation Candidate FP-1

Status: candidate, 2026-10-12. The user selected separate client-signed proofs
and gateway resource verification. Core/Open provider work does not constitute
PRAXOVELA/LIMENORA owner review or end-to-end production acceptance.

## Scope

This initial profile supports locally issued EIDOVELA registry-bound tokens
presented through an inspecting HTTP gateway. Peer and brokered identity context,
resource-query/body integrity, and token exchange at the proxy are not supported
by this candidate. Opaque HTTPS CONNECT tunnels are supported only under the
operator-configurable carriage/tunnel policy below; a raw tunnel with agent
processing selected and no accepted binding is denied, never treated as
NotApplicable. Routes requiring unsupported guarantees MUST NOT claim FP-1
conformance. Existing application authentication must not be replaced by optional
agent processing.

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

## Configurable Carriage and Tunnel Policy

Two operator-controlled, per-route policies decide where the resource proof is
carried and how an un-intercepted CONNECT tunnel is treated. Both are LIMENORA
`GATEWAY_*` configuration; PRAXOVELA aligns its client behavior to the same
profile. Neither is caller-supplied, and both are validated at startup.

`resource_proof_carriage`:

| Value | Carriage | Binding target (`htu`) | Requirement |
| --- | --- | --- | --- |
| `request_header` (default) | Dedicated proof header on the intercepted inner request | `scheme://host/path` (normalized) | Requires MITM interception of the route |
| `connect_header` | Dedicated proof header on the CONNECT request | `scheme://host:port` (authority only) | Explicit opt-in; path is not covered |
| `disabled` | None | — | Route must not require presentation |

`agent_tunnel_policy` (when a route requires presentation but traffic is a raw,
non-intercepted tunnel):

| Value | Behavior |
| --- | --- |
| `deny` (default) | Reject the agent request; never NotApplicable; never downgrade |
| `authority_binding` | Accept a `connect_header` proof bound to `host:port`; valid only together with `resource_proof_carriage=connect_header` |
| `passthrough_non_agent` | Allowed only when the route was not selected for agent processing; existing application auth continues |

Additional carriage parameters (also operator-configured and versioned):

- `resource_proof_header` — header name carrying the resource proof. Default
  `DPoP` for `request_header` mode (RFC 9449). `connect_header` mode uses a
  distinct, versioned name because RFC 9449 defines no CONNECT proof.
- `resource_proof_scheme` — authorization-scheme prefix, default `DPoP`.
- Introspection carriage uses EIDOVELA's fixed field `dpopProof` over a
  server-to-server channel; it is not caller-configurable.

These names are resolved from trusted route/gateway configuration, never from the
incoming request, and MUST NOT be derived from any caller-supplied header list.

`htu` is always derived from trusted routing under the selected mode, never from
caller `Forwarded`/`X-Forwarded-*` headers. In `request_header` mode the inner
request must actually be intercepted; a route that is not intercepted MUST NOT
fall back to authority binding. Query/fragment remain excluded in both modes.

Regardless of configuration:

- Presenter key = resource-proof key = EIDOVELA context `presenterJkt`; `ath` is
  the SHA-256 of the exact presented token; resource and introspection proof use
  distinct single-use `jti`.
- `disabled` or a key-only request is never a fallback after a configured verifier
  fails; provider outage, replay-store failure, and missing context deny.
- Invalid combinations (for example `authority_binding` without `connect_header`)
  fail startup validation rather than degrade silently.
- Proof headers (resource and introspection) are removed before the request is
  forwarded upstream, so no proof or token reaches the destination service.

Authority binding is a deliberately weaker guarantee (no path binding). Routes
that need path-level PoP MUST use `request_header` with interception; the default
posture denies un-intercepted agent traffic.

## Normative Target Normalization (`htu-normalization.v1`)

Both the gateway and EIDOVELA MUST implement byte-for-byte identical comparison.
Given a signed `htu` and the trusted request target:

1. Parse both as absolute URIs. Reject if the scheme is not `http`/`https`, the
   host is empty, userinfo is present, or the URI is opaque.
2. Compare scheme and host case-insensitively; do NOT strip or add default ports
   (an explicit `:443`/`:80` is significant).
3. Compare `EscapedPath()` byte-exactly: path case and percent-escapes are
   significant and a trailing `/` is distinct.
4. Ignore query and fragment entirely (RFC 9449); they are not integrity-protected.
5. `connect_header` (authority) mode compares scheme + host[:port] only.

No `Forwarded`/`X-Forwarded-*` header, proxy rewrite, dot-segment removal, or
percent-escape re-encoding may participate. Resource semantics that depend on
query/body require a separate, explicitly approved binding not defined here.

## Replay Ledger Contract

- Gateway resource-proof domain: `resource:` + `jti`, deployment-scoped;
  EIDOVELA introspection domain: `dpop:` + `jti` (existing). Domains MUST NOT
  collide.
- Consumption is atomic and shared across all gateway replicas (a shared store
  such as PostgreSQL); per-process memory is not acceptable for production.
- Retention MUST cover the full proof acceptance window (age + future skew) before
  a record may be pruned; pruning must never make a still-valid proof reusable.
- Storage failure denies the request; it never degrades to accept or to a
  process-local fallback.
- Retries always carry fresh `jti`; a consumed `jti` is never re-accepted.

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

Carriage, target normalization, the proof header/scheme, and the replay contract
are now frozen above; the header/scheme and carriage choices are
operator-configurable, and normalization and replay are normative. What remains
is implementation in PRAXOVELA (DPoP signing and carriage) and LIMENORA
(configuration, resource-proof verification, introspection call, and binding
dispatch), followed by FP-01 through FP-12 real-component acceptance. Until those
exist, federated production remains blocked. Local Core HTTP tests and Open SDK
tests are provider evidence only, not a complete federated presentation claim.

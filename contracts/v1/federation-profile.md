# EIDOVELA v1 Federation Profile

Verified downstream: an operator configures a peer EIDOVELA issuer (or a
conformant implementation) as a federation trust. EIDOVELA then introspects
tokens issued by that peer over the authoritative endpoint, so downstream and
console workflows can treat peer agents as verified.

## Trust administration

- `POST /v1/federation/trusts` — create or replace a trust (`FederationTrust`).
  Replacements revalidate the full configuration.
- `GET /v1/federation/trusts` — list trusts.
- `GET /v1/federation/trusts?issuer=<url>` — read a single trust.
- `POST /v1/federation/trusts/enable` / `disable` — transition status, with the
  issuer in the body (`{"issuer": "https://peer.example.com"}`).

Validation is fail closed: the issuer must be an absolute https URI (loopback
http allowed for development) and must not be the local authority; `jwks_uri`
must be absolute; `claim_mappings.agent_id` is required and `tenant_id` must not
be mapped (tenant always comes from the local request scope); `allowed_audiences`
must be non-empty. There is no delete: disable a trust to stop honoring it while
preserving the audit trail.

## Peer token profile

A peer must emit an EdDSA token that carries the EIDOVELA claim shape so
verification needs no per-peer semantics:

- header: `alg=EdDSA`, `kid` present;
- claims: `iss` = the peer issuer URI; `sub` = agent id; `aud` string or array;
  `iat`, `exp`; `jti`; `cnf.jkt` = RFC 7638 thumbprint of the presenter key.
  Peer-local claims (`agent_class`, `instance_id`, `workload_id`,
  `authority_root_ref`, `lifecycle_epoch`) are carried verbatim and never
  interpreted as local.

`claim_mappings` only aliases deviations from this shape (for example a non-`sub`
agent claim). It cannot weaken validation.

## Authoritative introspection

`POST /v1/introspect` with a peer-issued token returns `{"active": true}` only
when every check passes:

1. a trust exists for the tenant and issuer and is `active`;
2. the signature verifies under the peer's fetched JWKS (`kid` required,
   unknown-`kid` refresh is bounded, fetch failure denies);
3. the requested `audience` is in the trust's `allowed_audiences` and present in
   the token;
4. the token is time-valid;
5. the agent resolves through `claim_mappings`;
6. the presenter's `public_key` matches the token's `cnf.jkt`.

Any failure returns `{"active": false}`.

## Federation caveat to the revocation SLO

For federated tokens the peer is the lifecycle authority: EIDOVELA asserts what
it verified at presentation time (signature, time, audience, trust state, PoP)
but does not consult a local agent registry. Peer-side revocations already
expressed in the token (expiry, retired `kid` at the peer JWKS) are enforced
here; short-notice revocation is bounded by the JWKS cache TTL and the peer's own
introspection responsibility. This is a documented caveat, not a weakening of the
local revocation SLO.

## Offline consumers

Relying parties keep verifying EIDOVELA-issued tokens offline against
`GET /jwks.json`. Peer trust is only consulted for the authoritative online
`introspect` decision.

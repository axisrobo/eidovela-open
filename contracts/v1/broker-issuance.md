# EIDOVELA v1 Brokered Issuance

Import a verified external principal as a short-lived **local** PoP-bound token.

## Model

An operator broker/peer issuer is configured through the existing federation
trust surface (`POST /v1/federation/trusts`, active trust, `claim_mappings`,
`allowed_audiences`). The authority fetches the broker's JWKS from `jwks_uri`.

`POST /v1/broker/issue` imports an external assertion (a JWT signed under the
broker trust) into a local identity token:

- Request: `{"token": <broker assertion>, "audience": <allowed local audience>, "public_key": <presenter JWK>}`.
- The assertion must verify against an **active** broker trust: signature under
  the fetched JWKS, `aud` allowed and present, time-valid, the mapped agent
  claim present, and `cnf.jkt` equal to the presented `public_key` thumbprint.
- On success the response is a normal local token
  `{"token": "...", "expires_at": "..."}` whose `sub` is
  `fed:<broker issuer>/<mapped subject>`. It carries no local agent row and no
  lifecycle epoch; it is PoP-bound (`cnf.jkt`) and capped at the issuer TTL, so
  it expires (never needs a registry revocation).
- Authoritative `/v1/introspect` validates such tokens like any local token:
  active only under the bound PoP key, for the issued audience, until expiry.

## Guards

- Unknown/disabled broker issuers fail closed (`403`); a non-allowed audience or
  a PoP mismatch is denied.
- `sub` always encodes the external issuer (`fed:...`); no caller-supplied
  tenant, audience or authority root overrides verified sources.
- Broker/peer keys never enter the local registry; trust is via `/v1/federation/trusts`.

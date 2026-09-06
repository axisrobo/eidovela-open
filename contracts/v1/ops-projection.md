# EIDOVELA v1 Ops Projection

Read-only operational projections for console/ops. All responses are
**correlation-only**: they never contain tokens, private keys, proofs or
arbitrary request payloads.

## Endpoints

- `GET /v1/agents?state=<state>&limit=&offset=` — list tenant agents; `state`
  optional. Response `{"agents":[...]}`.
- `GET /v1/agents/{id}` — single agent detail (`Agent`/`AgentSummary` shape).
- `GET /v1/agents/{id}/instances?limit=&offset=` — instances bound to an agent
  (including `lease_expires_at` and a read-only derived `lease_expired` when the
  lease is set and lapsed).
- `GET /v1/evidence?event_type=&since=<RFC3339>&limit=&offset=` — paginated
  redacted evidence (ordered by creation); `since` keeps events at/after the
  timestamp.
- `GET /v1/ops/outbox` — read-only outbox health
  `{published,pending,leased,dead_lettered}`.
- `GET /v1/ops/counters` — aggregate `{"evidence":{"<event_type>":count}}`.
- `GET /v1/federation/trusts/status` — configured trusts merged with per-issuer
  introspection outcome telemetry `{issuer,status,success,deny}` (process-local).

## Pagination and guards

- `limit` defaults to 100, capped at 1000; `offset` starts at 0. Both are
  tenant-scoped and server-validated. An explicit `limit=0` is honored (empty
  page); omit `limit` for the default.
- List responses use stable envelope keys: `agents`, `instances`, `evidence`,
  `trusts`; detail (`GET /v1/agents/{id}`) returns the single object without an
  envelope.
- Filters (`state`, `event_type`, `since`) are applied server side before paging.
- Offset pagination is the v1 choice; an opaque cursor (e.g. `since` on
  evidence) is a documented follow-on and would be additive if adopted.
- Read endpoints never bypass audit: they read the same redacted projection the
  lifecycle stream and outbox expose, never raw tables with sensitive payloads.

## Scope notes

This profile is additive on the stable v1 line (new endpoints only). Telemetry
counters are per-process and reset on restart; treat them as health signals, not
as durable audit (durable history stays in `evidence_events`/outbox).

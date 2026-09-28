# EIDOVELA v2 Contracts

The `v2` contract line reflects the **Registry Separation Baseline**: EIDOVELA is
an Agent Identity Provider and authentication authority, and the NOMIVELA Agent
Registry is authoritative for Agent, Agent ID, Authority Binding, Workload
Registration and Agent Instance records.

`v1` remains published and frozen. `v2` is the line for consumers that integrate
with EIDOVELA in registry-consumer mode.

## What changed from v1

| Area | v1 | v2 |
|---|---|---|
| Agent registry | EIDOVELA authored Agent, Agent ID and Authority Binding | NOMIVELA authors them; EIDOVELA consumes them read-only |
| Agent lifecycle | `registered` / `enrolled` / `active` / `suspended` / `revoked` | NOMIVELA `agent_state` and `identity_state` |
| Epoch | single `lifecycle_epoch` | dual `agent_epoch` and `identity_epoch` |
| Blueprint | EIDOVELA-owned `agent-blueprint` | external reference only |
| Registry writes | `POST /v1/agents`, blueprints, workload registrations, instance lease/terminate | retired with `410 write_authority_moved` |
| Registry reads | `GET /v1/agents` | `GET /v1/registry/*` plus read-only compatibility aliases |

## Endpoints

Retired (respond `410 Gone` with code `write_authority_moved`):

```text
POST /v1/agents
POST /v1/agents/{id}/activate
POST /v1/agents/{id}/suspend
POST /v1/agents/{id}/revoke
POST /v1/blueprints
POST /v1/blueprints/{id}/publish
POST /v1/blueprints/{id}/deprecate
POST /v1/workload-registrations
POST /v1/instances/{id}/lease
POST /v1/instances/{id}/terminate
```

New read views:

```text
GET /v1/registry/agents
GET /v1/registry/agents/{agentID}
GET /v1/registry/agents/{agentID}/instances
GET /v1/registry/workload-registrations
GET /v1/verified-agent-context?agent_id=...&instance_id=...
```

EIDOVELA-owned authentication authority:

```text
GET  /v1/credentials?agent_id=...
POST /v1/credential-revocations
GET  /v1/authentication-state
GET  /v1/authentication-state/{agentID}
POST /v1/authentication-state/{agentID}/quarantine
POST /v1/authentication-state/{agentID}/disable
POST /v1/authentication-state/{agentID}/reinstate
GET  /v1/attestations/{attestationRef}
```

Unchanged in v2: `/oauth2/token`, `/v1/token/exchange`, `/v1/introspect`,
`/v1/enrollments`, `/v1/enrollments/complete`, federation, broker issuance,
evidence and operations.

## Token profile

Identity tokens carry `agent_epoch` and `identity_epoch`. `lifecycle_epoch` is
retained for legacy verifiers and mirrors `agent_epoch`. A change to either
registry epoch invalidates an unexpired token on online verification.

## Contents

- `verified-agent-context.schema.json`
- `registry-agent.schema.json`
- `registry-instance.schema.json`
- `registry-workload-registration.schema.json`
- `authentication-state.schema.json`
- `credential.schema.json`
- `attestation-result.schema.json`

## Stability

`v2` is a new, additive contract line. Within `v2`, additive evolution is allowed
only when consumers can ignore new fields; removing required fields,
reinterpreting semantics or narrowing enums requires a new contract line.

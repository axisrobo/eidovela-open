# Agents

## EIDOVELA Agent Identity Provider (IdP)

EIDOVELA is a native **Agent Identity Provider (IdP)** for agent-based private-cloud systems. Key capabilities:

- **Registry consumption**: Agent, Agent ID, Authority Binding, Workload Registration and Agent Instance are read from the NOMIVELA Agent Registry; EIDOVELA does not author them.
- **Workload enrollment**: private_key_jwt proof of possession with kubernetes/spiffe/mTLS attestation, verified in EIDOVELA when trust is configured.
- **Authentication and STS**: OIDC discovery, JWKS, short-lived PoP identity tokens, exchange, introspection.
- **Dual-epoch binding**: tokens carry `agent_epoch` and `identity_epoch`; either registry transition invalidates an unexpired token.
- **Credential lifecycle**: credential generations, revocation and authentication quarantine/disable.
- **Federation foundation**: verified downstream trust and broker issuance.

Public contracts for this model are in [`contracts/v2`](contracts/v2/README.md); `contracts/v1` is frozen for existing consumers.

## Repositories

| Repo | License | Version tag | Contents |
|---|---|---|---|
| `eidovela` (core) | AGPL-3.0-or-later | Shared with open | Core identity plumbing |
| `eidovela-open` (this repo) | Apache-2.0 | Shared with core | Public contracts, SDKs, CLI, examples, conformance |
| `eidovela-ee` (enterprise) | Proprietary/SAAS | Independent | HSM/KMS, advanced federation, console |

## Agent workflow

1. **Resolve** a Registry-owned Agent, Agent ID, Workload Registration and lifecycle epochs from NOMIVELA
2. **Enroll** via private_key_jwt with verified workload evidence
3. **Activate** authentication credentials for the Registry-authorized lifecycle state
4. **Issue** a PoP-bound short-lived token carrying `agent_epoch` and `identity_epoch`
5. **Introspect** the token with audience and registry-state verification
6. **Federate** to downstream systems if configured

## Key components

- `registryclient.Reader` — Read-only NOMIVELA registry consumer
- `authentication` — Credential generations and authentication state (quarantine/disable)
- `enrollment` — Proof-of-possession plus workload attestation, commits the Agent Instance to NOMIVELA
- `sts` — Dual-epoch PoP identity tokens, exchange and introspection
- `contracts/v2` — Public contracts for the registry-consumer model

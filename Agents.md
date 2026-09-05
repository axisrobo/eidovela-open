# Agents

## EIDOVELA Agent Identity Provider (IdP)

EIDOVELA is a native **Agent Identity Provider (IdP)** for agent-based private-cloud systems. Key capabilities:

- **Agent lifecycle management**: Register, Enroll, Activate, Suspend, Revoke
- **Tenant-scoped trust domains**: Validated via `tenant_trust_domains` table
- **Platform recognition**: kubernetes, spiffe, mTLS workload attestation
- **private_key_jwt enrollment**: JWT-based proof-of-possession
- **Lifecycle-aware token issuance**: Tokens bound to agent epoch and state
- **Federation foundation**: Verified downstream for console and federation workflows

## Repositories

| Repo | License | Version tag | Contents |
|---|---|---|---|
| `eidovela` (core) | AGPL-3.0-or-later | Shared with open | Core identity plumbing |
| `eidovela-open` (this repo) | Apache-2.0 | Shared with core | Public contracts, SDKs, CLI, examples, conformance |
| `eidovela-ee` (enterprise) | Proprietary/SAAS | Independent | HSM/KMS, advanced federation, console |

## Agent workflow

1. **Register** agent with tenant and class (twin/service/ephemeral)
2. **Enroll** via private_key_jwt with workload attributes
3. **Activate** agent lifecycle state
4. **Issue** PoP-bound short-lived token
5. **Introspect** token with audience verification
6. **Federate** to downstream systems if configured

## Key components

- `tenant_trust_domains` — Table enforcing which trust domains are valid per tenant
- `ClassTwin / ClassService / ClassEphemeral` — Agent class types
- `WorkloadRegistration` — Contains platform, selector, trust_domain
- `agent_instances` — Persists attestation_ref, lifecycle epoch
- `enrollment.Complete` — Ties proof-of-possession to agent binding

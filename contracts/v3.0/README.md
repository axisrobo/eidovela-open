# EIDOVELA v3.0 Contracts

The `v3.0` contract line applies the Agent IAM Series contract conventions
(`agent-iam-spec` RFC-0003) to the Registry Consumer line:

- wire field names are `lowerCamelCase`;
- reference fields use the `…Ref` suffix (`agentRef`, `authorityRootRef`,
  `sponsorRef`, `workloadRegistrationRef`, `instanceRef`);
- the dual epochs `agentEpoch` and `identityEpoch` are carried explicitly;
- the Agent class vocabulary is the unified nine-class set;
- `tenant_id` is no longer an interoperable claim and is not present in the
  contexts and views.

`v2` remains published and frozen for consumers that integrate with the previous
snake_case, `tenant_id`-bearing line. `v1` and `v1alpha1` remain published.

## What changed from v2

| Area | v2 | v3.0 |
|---|---|---|
| Field naming | `snake_case` (`agent_id`, `authority_root_ref`) | lowerCamelCase (`agentId`, `authorityRootRef`) |
| Tenant | required `tenant_id` | removed; `namespace` is the only anchor |
| References | mixed | `…Ref` suffix for references, `…Id` for identifiers |
| Epochs | `agent_epoch` / `identity_epoch` | `agentEpoch` / `identityEpoch` |
| Agent class | `twin` / `service` / `ephemeral` | unified nine-class set |

## Contents

- `verified-agent-context.schema.json`
- `registry-agent.schema.json`
- `registry-instance.schema.json`
- `registry-workload-registration.schema.json`
- `authentication-state.schema.json`
- `credential.schema.json`
- `attestation-result.schema.json`

## Stability

`v3.0` is a new, incompatible contract line. Within `v3.0`, additive evolution is
allowed only when consumers can ignore new fields; removing required fields,
reinterpreting semantics, or narrowing enums requires a new contract line.

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

`verified-agent-context.schema.json` additionally exposes the registry-owned
`identityType` and, when applicable, `subjectRef` (additive). This requires
NOMIVELA SDK v2.1.0 or later; legacy identities surface an empty `identityType`.

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

## Candidate Presentation Profile

`federated-presentation.md` specifies FP-1 separate resource/introspection proofs
and the additive opt-in token-bound context API. Its response/request definitions
are in `token-context-introspection.schema.json`. This candidate is not a claim
of PRAXOVELA/LIMENORA production conformance; gateway transport and end-to-end
acceptance remain release gates. Existing contracts above are not reinterpreted.

## SDK

The Go client for this line is
[`sdk/go/eidovela/v3`](../../sdk/go/eidovela/v3). The frozen
[`sdk/go/eidovela`](../../sdk/go/eidovela) package targets the v2 snake_case wire
and is unchanged.

## Stability

`v3.0` is a new, incompatible contract line. Within `v3.0`, additive evolution is
allowed only when consumers can ignore new fields; removing required fields,
reinterpreting semantics, or narrowing enums requires a new contract line.

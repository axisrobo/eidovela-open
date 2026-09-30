# Contract Compatibility

The `v3.0` Registry Consumer line is the current contract. It applies the Agent
IAM Series contract conventions (RFC-0003): camelCase field names, `…Ref`
references, the dual `agentEpoch` / `identityEpoch`, the unified nine-class Agent
set, and no required `tenant_id`. It consumes the Agent Registry contract
`agent-registry-v1.0`.

The `v2` Registry Consumer line (snake_case, required `tenant_id`) is frozen for
existing consumers; the `v1` contract line is frozen for earlier consumers;
`v1alpha1` remains published for compatibility with older consumers.

Within a line, fields may be added only when consumers can ignore them.
Required-field removal, semantic reinterpretation, enum narrowing and
serialization changes require a new version directory.

Conformance fixtures (`conformance/fixtures`) are normative for rejection
behavior: unknown issuer/audience/key, wrong PoP key/workload, dual stale epoch,
registry instance termination, exchange widening, token-proof replay, workload
attestation mismatches, revocation SLO and cross-audience introspection.

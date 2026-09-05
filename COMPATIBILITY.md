# Contract Compatibility

The `v1` contract line is the stable wire contract. `v1alpha1` remains
published for compatibility with earlier consumers but is not the default.

Within a line, fields may be added only when consumers can ignore them.
Required-field removal, semantic reinterpretation, enum narrowing and
serialization changes require a new version directory.

Conformance fixtures (`conformance/fixtures`) are normative for `v1` rejection
behavior: unknown issuer/audience/key, wrong PoP key/workload, stale epoch,
retired signing key, exchange widening, token-proof replay, workload
attestation mismatches, revocation SLO and cross-audience introspection.

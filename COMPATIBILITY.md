# Contract Compatibility

The `v2` Registry Consumer line is the default contract. It consumes NOMIVELA
Agent Registry contract `1.0.0` through `github.com/axisrobo/nomivela-open/v2`.
The `v1` contract line is frozen for earlier consumers; `v1alpha1` remains
published for compatibility with older consumers.

Within a line, fields may be added only when consumers can ignore them.
Required-field removal, semantic reinterpretation, enum narrowing and
serialization changes require a new version directory.

Conformance fixtures (`conformance/fixtures`) are normative for `v2` rejection
behavior: unknown issuer/audience/key, wrong PoP key/workload, dual stale epoch,
registry instance termination, exchange widening, token-proof replay, workload
attestation mismatches, revocation SLO and cross-audience introspection.

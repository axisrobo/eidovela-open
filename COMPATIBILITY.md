# Contract Compatibility

Within `v1alpha1`, fields may be added only when consumers can ignore them. Required-field removal, semantic reinterpretation, enum narrowing and serialization changes require a new version directory.

Fixtures are normative for rejection behavior: unknown issuer/audience/key, wrong PoP key/workload, stale epoch, retired signing key, exchange widening and token-proof replay.

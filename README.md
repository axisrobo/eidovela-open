# EIDOVELA Open

Public contracts, SDKs, CLI, examples and conformance fixtures for EIDOVELA — the Agent Identity Provider & Authentication Authority.

- Module: `github.com/axisrobo/eidovela-open`
- License: Apache-2.0
- Core implementation (AGPL): https://github.com/axisrobo/eidovela

Contents:

- `contracts/` — versioned public contract schemas (v1alpha1)
- `sdk/go` — Go SDK
- `cli/` — command-line tool
- `examples/` — integration examples
- `conformance/` — positive/negative issuer & verifier fixtures

Version format: `major.minor.patch`. Current: 0.1.0.

## v0.5 local loop

Start the core daemon, then run the public example:

```text
eidovelad
go run ./examples/local-loop
```

The example registers a Service Agent, registers a workload profile, completes
`private_key_jwt` enrollment, activates the Agent, obtains a short-lived
PoP-bound token, then authoritatively introspects it.

The Go SDK is available at `sdk/go/eidovela`. It contains the HTTP client,
Ed25519 PoP key generation and offline JWT/JWKS verification. Offline
verification does not check the current lifecycle epoch; high-risk consumers
must use authoritative introspection.

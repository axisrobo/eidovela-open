# Internal (non-HTTP) Fixtures

These fixtures describe verifier/issuer-internal semantics that are **not**
observable through the public HTTP surface and therefore cannot be driven by
`cmd/eidovela-conformance`:

| Fixture | Semantics | Covered by (core) |
|---|---|---|
| `N-G1-1.unknown-issuer.json` | Token from an unknown issuer is rejected | `internal/sts/issuer_test.go` `TestVerifyUnknownIssuer` |
| `N-T3-1.tenant-override.json` | Caller-supplied tenant cannot override the verified issuer/binding mapping | registry store tenant isolation tests |
| `N-T6-1.expired-rotated-kid.json` | Token signed by a retired key fails after the overlap window | `internal/sts/issuer_test.go` `TestRotationPublishesOverlappingKeyThenExpiresIt` |
| `N-F1-7.unknown-rotated-kid.json` | Peer token signed by a retired/unknown `kid` fails closed | `internal/federation/verify_test.go` `TestVerifierIntrospectRefreshesRotatedKey`, key cache fail-closed tests |
| `N-F1-8.local-issuer-collision.json` | A trust cannot point at the local authority | `internal/federation/admin_test.go` `TestValidateTrustConfig` (local-issuer case), httpapi admin loop 400 |
| `N-F1-9.plaintext-remote-uri.json` | Plaintext non-loopback JWKS/issuer rejected at write and fetch | `internal/federation/admin_test.go` `TestValidateTrustConfig`, `internal/federation/jwks_test.go` |

They are retained as a declarative record of the threat expectations. The
authoritative, executable assertions live in the core unit tests referenced
above.

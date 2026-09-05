# EIDOVELA v1alpha1 Token Proof Profile

`POST /oauth2/token` requires `proof_jwt` and `public_key`.

The proof is an EdDSA `private_key_jwt` signed by `public_key`:

| Claim | Required value |
|---|---|
| `iss` | Requested Agent ID |
| `sub` | Requested bound Instance ID |
| `aud` | `eidovela:token` |
| `jti` | Unique, one-time value per tenant |
| `exp` | Short-lived future timestamp |

The server verifies signature and claims, then atomically consumes `jti`. Reused, expired, malformed or incorrectly bound proofs are denied. The request public key must also be an active Agent credential.

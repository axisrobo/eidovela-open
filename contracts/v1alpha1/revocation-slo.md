# EIDOVELA v1alpha1 Revocation SLO

**SLO:** a revoked agent is denied immediately by the authoritative authority.

At the instant an agent transitions to `revoked`:

1. New token issuance for the agent fails.
2. Previously issued tokens fail **online** verification (`active: false` on
   the authoritative introspection endpoint).
3. The agent lifecycle is terminal.

There is no propagation delay: online verification and the `introspect`
endpoint consult authoritative registry state on every call.

## Offline verification caveat

Offline JWT/JWKS verification validates signature and claims only. It does not
consult lifecycle state, so a token can still verify locally after revocation.
High-risk consumers must use the authoritative introspection endpoint, which
checks agent lifecycle state and epoch.

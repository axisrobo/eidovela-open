# EIDOVELA v1 Instance Lease

Instance leases make workload-instance authorization decay with the instance
lifecycle. `agent-instance.schema.json` already publishes `lease_expires_at`;
this profile makes leases observable and enforceable over HTTP.

## Endpoints

- `POST /v1/instances/{id}/lease` — body `{"lease_expires_at": "<RFC3339>"}`.
  Binds the instance to an expiry and moves it to `active`. The lease must be in
  the future and within the server-configured maximum duration. Requires the
  instance to exist and not be `terminated`.
- `POST /v1/instances/{id}/terminate` — moves the instance to the terminal
  `terminated` state. A terminated instance cannot request tokens and cannot be
  leased again.

Both return the updated `AgentInstance`.

## Enforcement gate

Token issuance (`/oauth2/token`) denies an instance **whose lease is set** when
the lease has expired. Instances with no lease keep the legacy unlimited
semantics, so lease enforcement is additive and does not change existing
consumers.

## Token-vs-lease asymmetry

Lease passage does not bump the agent lifecycle epoch. It only prevents **new**
tokens: a short-lived token issued while the lease was valid continues to verify
and introspect until the token itself expires. If an instance must be stopped
immediately, terminate it (termination is immediate and terminal) rather than
letting the lease lapse.

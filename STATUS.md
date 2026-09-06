# Open Distribution Status

**Version:** 1.8.0 | **Contract line:** v1 (stable, additive increments)

Published: v1 contract schemas and protocol profiles (agent/blueprint/identity/
instance/binding/workload-registration and `federation-trust`; enrollment
attestation, revocation SLO, token proof, federation, instance lease,
**broker-issuance** and **ops-projection** profiles), Go SDK (registration,
enrollment with platform attestation, lifecycle ops incl. suspend/revoke reason,
token, audience-aware introspect, exchange, federation trust administration,
instance lease/terminate, blueprint register/publish/deprecate/list, brokered
issuance, signing-key custody status/rotate, and read projections for
agents/instances/evidence/outbox rows/federation status with opaque cursor
pages), CLI, local-loop example and an executable HTTP conformance runner (PoP
binding, attestation, lifecycle/revocation incl. suspend reason, exchange,
audience, federation, instance lease, blueprint lifecycle, cursor pagination,
brokered issuance, outbox rows). `v1alpha1` is retained for earlier consumers.

This repository publishes released public contracts and distribution status only.
Internal product roadmap and unreleased plans remain in the private EE repository.

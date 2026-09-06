# Open Distribution Status

**Version:** 1.3.0 | **Contract line:** v1 (stable, additive increments)

Core v1.3 (shared tag) exposes the public `provider`/`server` extension surface
for external signing-key custody; this distribution's wire contracts are
unchanged. Published: v1 contract schemas and protocol profiles (agent/blueprint/identity/
instance/binding/workload-registration and `federation-trust`; enrollment
attestation, revocation SLO, token proof, federation and instance lease
profiles), Go SDK (agent/workload registration, enrollment with platform
attestation, activation/suspension/revocation, token, audience-aware introspect,
exchange, federation trust administration, instance lease/terminate), CLI,
local-loop example and an executable HTTP conformance runner with step-based
fixtures (PoP binding, attestation, lifecycle/revocation, exchange, audience,
federation, instance lease). `v1alpha1` is retained for earlier consumers.

This repository publishes released public contracts and distribution status only.
Internal product roadmap and unreleased plans remain in the private EE repository.

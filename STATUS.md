# Open Distribution Status

**Version:** 2.2.0 | **Contract line:** v2 (Registry Consumer); v1 frozen

Published: v2 Registry Consumer schemas for the verified Agent context, Registry
Agent/Instance/Workload views, authentication state and credential lifecycle;
the stable v1 protocol profiles remain available for earlier consumers. The Go
SDK, CLI and executable HTTP conformance runner now exercise a consumer-mode
daemon backed by a NOMIVELA test double: PoP binding, attestation, dual epoch
lifecycle invalidation, token exchange, audience binding, federation, registry
instance state, brokered issuance and outbox rows. `v1alpha1` is retained for
earlier consumers.

This repository publishes released public contracts and distribution status only.
Internal product roadmap and unreleased plans remain in the private EE repository.

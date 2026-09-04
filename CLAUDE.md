# EIDOVELA Open — Agent Guide

## Harness

This repository uses **superpowers** as the agent harness (`.claude/settings.json` → `superpowers@superpowers-marketplace`). Use superpowers skills/workflows when executing tasks.

## Repository

- Product: EIDOVELA — public contracts, SDKs, CLI, examples, conformance fixtures
- Module: `github.com/axisrobo/eidovela-open`
- License: Apache-2.0
- Core implementation (AGPL): `github.com/axisrobo/eidovela`

## Conventions

- Version format: `major.minor.patch` (see `VERSION`)
- Contract schemas are versioned under `contracts/<version>/`; v1alpha1 is frozen once published — additive changes only, breaking changes require a new contract version
- Nothing in this repo may depend on `eidovela` (AGPL) or `eidovela-ee`; the dependency direction is core/EE → open
- Conformance fixtures must include positive and negative cases (unknown issuer/audience/key/tenant, stale epoch, wrong workload binding)

## Commands

- Build: `go build ./...`
- Vet: `go vet ./...`
- Test: `go test ./...`

# EIDOVELA Open — Agent Guide

## Harness

This repository uses **superpowers** as the agent harness (`.claude/settings.json` → `superpowers@superpowers-marketplace`). Use superpowers skills/workflows when executing tasks.

## Repository

- Product: EIDOVELA — public contracts, SDKs, CLI, examples, conformance runner
- Module: `github.com/axisrobo/eidovela-open`
- License: Apache-2.0
- Core implementation (AGPL): `github.com/axisrobo/eidovela`

## Conventions

- Version format: `major.minor.patch` (see `VERSION`); current line is v0.5 Contract Foundation
- Contract schemas are versioned under `contracts/<version>/`; v1alpha1 is frozen once published — additive changes only, breaking changes require a new contract version
- Nothing in this repo may depend on `eidovela` (AGPL) or `eidovela-ee`; the dependency direction is core/EE → open
- Conformance fixtures (`conformance/fixtures`) must include positive and negative executable scenarios; verifier/issuer-internal semantics that are not observable over HTTP belong in `conformance/fixtures-internal` and are covered by core unit tests
- The committed `conformance/bin/` daemon is the AGPL core binary, present so the runner can drive a live daemon without a core checkout

## Commands

- Build: `go build ./...`
- Vet: `go vet ./...`
- Test: `go test ./...`
- Local CI: `bash scripts/ci` (builds the daemon when `conformance/bin` lacks a platform binary; set `EIDOVELA_CORE_DIR` to a core checkout)
- Conformance (against a running daemon): `go run ./cmd/eidovela-conformance -server <base-url>`

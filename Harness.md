# Harness

## Agent harness

This project uses **superpowers** as the agent harness (`.claude/settings.json` → `superpowers@superpowers-marketplace`). Use superpowers skills/workflows when executing tasks.

## Versioning rules

- **Format:** `major.minor.patch` (e.g. `0.1.0`, `0.3.0`).
- **`eidovela-open` and `eidovela` (core) share the same version tag.** When either repository ships a change that warrants a bump, both are tagged with the same version (e.g. `v0.1.0`, `v0.2.0`, `v0.3.0`).
- **`eidovela-ee` (enterprise) has an independent tag** and is not synchronized with core/open (e.g. `v0.3.0-ee.1`).
- Version source of truth: `VERSION` in each repository.
- Contract schemas are versioned under `contracts/<version>/`; v1alpha1 is frozen once published — additive changes only, breaking changes require a new contract version.

## Release workflow

1. Implement the feature/fix on `main`.
2. Run `go build ./...`, `go vet ./...`, `go test ./...` — must be clean.
3. Bump `VERSION` in core and open to the same value (EE independently).
4. Tag both `eidovela-open` and `eidovela`: `git tag v0.N.0`; push tags to origin.
5. Update `STATUS.md`, `COMPATIBILITY.md` as needed.

## Dependency direction

Nothing in `eidovela-open` may depend on `eidovela` (AGPL) or `eidovela-ee`; the dependency direction is core/EE → open.

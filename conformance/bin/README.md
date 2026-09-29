# eidovela core daemon binary (for conformance)

The executable conformance runner (`cmd/eidovela-conformance`) and the fixture
suite drive a live EIDOVELA **core** issuer daemon
(`github.com/axisrobo/eidovela`, AGPL-3.0-or-later) from this directory.

The binary is **not** committed. This directory is gitignored; the conformance
scripts and CI build the daemon here on demand, so a separate core checkout is
required only to run the suite, not to build this repository.

## License

The daemon is licensed under **AGPL-3.0-or-later**. This Apache-2.0 repository
builds it solely to run the conformance scenarios against an authoritative
implementation. No AGPL binary is redistributed.

## Building

```text
# from a checkout of github.com/axisrobo/eidovela (backend/)
go build -o ../../eidovela-open/conformance/bin/eidovelad ./cmd/eidovelad
```

`conformance/scripts/ci` (Linux/macOS) and `conformance/scripts/ci.ps1`
(Windows) build the daemon automatically when the platform binary is absent,
and the runner skips cleanly when no binary is present.

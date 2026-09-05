# eidovela-core daemon binary (for conformance)

`eidovelad.exe` is a prebuilt Windows binary of the EIDOVELA **core** issuer
(`github.com/axisrobo/eidovela`, AGPL-3.0-or-later). It is committed here so
the executable conformance runner (`cmd/eidovela-conformance`) and local CI can
drive a live daemon without requiring a separate checkout of the core
repository.

## Provenance and license

- Source: <https://github.com/axisrobo/eidovela>
- Built from the version tagged alongside this distribution (see `VERSION`).
- The binary is licensed under **AGPL-3.0-or-later**. Redistribution must comply
  with that license. This Apache-2.0 repository includes it solely to run the
  conformance scenarios against an authoritative implementation.

## Building for another platform

The committed binary is built for Windows. To run conformance on Linux/macOS,
build the daemon for the current platform and place it at `conformance/bin/`:

```text
# from a checkout of github.com/axisrobo/eidovela (backend/)
go build -o ../../eidovela-open/conformance/bin/eidovelad ./cmd/eidovelad
```

`conformance/scripts/ci` (Linux/macOS) and `conformance/scripts/ci.ps1`
(Windows) build the daemon automatically when the platform binary is absent.

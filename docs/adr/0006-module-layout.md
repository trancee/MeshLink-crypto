# Module layout: single shared KMP module

## Status

accepted

## Context

KMP crypto can be one shared module (`commonMain` + per-target `actual`s) or split
per algorithm family. The shared 10-limb field engine (ADR-0001) serves both X25519
and Ed25519, so the modules are coupled by that engine.

## Decision

**Single shared `crypto` module**: `commonMain` defines the `expect` API + the
pure-K engine; `jvmMain`/`androidMain`/`iosMain` provide `actual` native dispatch
per primitive (ADR-0002).

## Consequences

- The field engine lives once in `commonMain`, shared by X25519 + Ed25519; each
  primitive's native `actual` is independent.
- Real alternative "split per family" was rejected: it would duplicate the shared
  field engine and multiply the native interop bindings per module.
- Trade-off: a larger single module; acceptable given the shared-engine coupling.

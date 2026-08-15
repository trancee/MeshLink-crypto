# Tooling decision: SKIE excluded (for now)

## Status

accepted

## Context

[SKIE](https://skie.co) is a Kotlin Multiplatform tool that (a) prevents Kotlin/Native
reference-cycle leaks, (b) bridges Kotlin coroutines/`Flow` to Swift concurrency, and (c) improves
Objective-C/Swift interop quality (exception handling, cleaner selectors). Question raised: include
it in crypto-kmp's build?

Targets: JVM + Android API 21+ + iOS arm64. Public API is **stateless, synchronous, no-throw**
(`Result<T>`), with an internal AEAD nonce and typed wiping key handles (ADR-0005).

## Decision

Do **not** use SKIE in the initial module.

- **No coroutines / `Flow`** → SKIE's headline Swift-concurrency bridge is unused.
- **No Kotlin exceptions cross the KMP boundary** → the `Result<T>` design (ADR-0005) already makes
  exception↔Swift mapping moot.
- **Pure arithmetic** over `ByteArray`/`Long`/`Int` creates no Kotlin/Native reference cycles →
  SKIE's leak collector has no cycle to collect.
- iOS native interop is **cinterop to C frameworks** (CommonCrypto / Security), not Kotlin APIs as
  the primary Swift surface → only marginal selector/exception polish, which the no-throw API already
  makes unnecessary.

## Consequences

- Avoids an extra Gradle plugin dependency and build-config surface (keep the build boring).
- Re-evaluate (this ADR → "adopt SKIE") only if (i) the iOS `actual` exposes Kotlin-callable APIs to
  Swift where interop signatures or exception mapping prove insufficient, or (ii) a reference-cycle
  leak is observed in the iOS native path. Currently neither is expected.

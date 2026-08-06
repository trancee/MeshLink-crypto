# 01 — Scaffold the KMP module + build toolchain

A single shared Kotlin Multiplatform module for the crypto primitives, wired with the
build quality toolchain (ADR-0007: `ktfmt` + `detekt` + `kover`, 100% coverage on the pure-K path).

Status: ready-for-agent

Blocked by: None

## What to build

- Kotlin Multiplatform module `crypto-kmp` with targets: **JVM**, **Android (API >= 21)**,
  **iOS arm64 (Darwin)**. **Exclude** JS and Kotlin/Native WASM targets.
- Kotlin **2.4.10** (pin in `libs.versions.toml` / Gradle).
- Version catalog (`gradle/libs.versions.toml`) — no BouncyCastle / `javax`/`java.security` in
  `commonMain`; only the 7 RFC texts in `docs/rfcs/crypto/` as references.
- Toolchain wired and CI-enforced:
  - **ktfmt**: `./gradlew format` applies; `verify` fails on unformatted code.
  - **detekt**: `./gradlew detekt` passes (incl. the ADR-0003 constant-time rule from ticket 02).
  - **kover**: coverage report + CI gate = 100% on the pure-K path.
- Build tasks: `./gradlew check` runs format-verify + detekt + unit tests + kover on JVM, Android,
  and iOS (Darwin) simulators/VMs.

## Acceptance

- [ ] `./gradlew tasks` succeeds; only JVM + Android + iOS targets configured (no JS/WASM).
- [ ] Kotlin pinned to 2.4.10 (`./gradlew -v` shows the toolchain).
- [ ] `format`/`verify` task exists; a planted unformatted line fails `verify`.
- [ ] `./gradlew detekt` passes on the empty module.
- [ ] `./gradlew koverXmlReport` produces a report; no `java.security`/`BouncyCastle` dependency
  declared in `commonMain` (grep-clean).

## Notes

- This is the true root: every other ticket is `Blocked by` it.
- Native-fallback deps (`java.security`, Android KeyStore, iOS CommonCrypto/Security) are added via
  `expect/actual` per-ticket (see ADR-0002); do NOT pull them into `commonMain` here.

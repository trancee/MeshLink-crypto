# Constitution — MeshLink-crypto Quality Gates

This document defines the non-negotiable quality gates that every commit to
`main` must pass. It is the single source of truth for what "production ready"
means for this repository. Code owners enforce it via CODEOWNERS review.

## 1. Constant-time discipline

- All secret-handling code lives exclusively in `crypto/src/commonMain/kotlin/`.
- The custom `ConstantTimeRule` (detekt) bans data-dependent branching and
  secret-indexed array access on `@Secret`-annotated parameters.
- 100% branch + line coverage on the pure-K path (kover gate: `minBound(100)`).
- Wycheproof vectors are the correctness oracle for every primitive.
- No `BigInteger` in pure-K paths (ADR-0001).

## 2. Per-primitive native fallback

- Each primitive has an independent native-or-pure-K dispatch path (ADR-0002).
- Native dispatch uses platform providers (JCA, CommonCrypto, Security.framework).
- The pure-K path is the fallback when native is unavailable.

## 3. Build toolchain

- Kotlin 2.4.10 (pinned in `gradle/libs.versions.toml`).
- JDK 21 toolchain.
- ktfmt for formatting, detekt for linting, kover for coverage,
  ABI validation via `kotlin { abiValidation {} }` (ADR-0007).
- `./gradlew check --rerun --no-build-cache` must pass locally before PR.

## 4. Benchmarks

- Every primitive has a JMH benchmark in `crypto/src/jvmBenchmark/` (ADR-0009).
- Code changes to pure-K primitives require a before/after comparison.
- >10% regression on any benchmark blocks merge.

## 5. CI

- CI runs on `macos-latest` (required for iOS KMP compilation).
- CI gates: detekt + kover + spotless + ABI validation + JVM tests +
  iOS simulator tests.
- The CI summary shows kover coverage + test results inline in the Actions
  run summary (no artifact download needed).

## 6. Release

- Releases use Conventional Commits.
- Publishing to Maven Central requires GPG-signed artifacts.
- The release workflow (`.github/workflows/publish.yml`) runs on `v*` tags.
- Security advisories are reported via `SECURITY.md`.

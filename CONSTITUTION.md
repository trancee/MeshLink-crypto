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
- `./gradlew check --rerun-tasks --no-build-cache` must pass locally before PR.

## 4. CI

- CI runs on `macos-latest` (required for iOS KMP compilation).
- CI gates: detekt + kover + spotless + ABI validation + JVM tests +
  iOS simulator tests.
- Android SDK matrix verifies compilation across API 21/28/29/37.
- The CI summary shows kover coverage + test results inline in the Actions
  run summary (no artifact download needed).

## 5. Release

- Releases use Conventional Commits.
- Publishing to Maven Central requires GPG-signed artifacts.
- The release workflow (`.github/workflows/publish.yml`) runs on `v*` tags.
- **Docs alignment:** `docs/reference/api-reference.md` and `docs/reference/supported-primitives.md` must reflect the current public API before every tag. The javadoc JAR bundles these markdown files alongside Dokka HTML (ADR-0007).
- **ABI baseline:** `kotlin { abiValidation {} }` dump (`crypto/api/crypto.klib.api`) must be regenerated when public API changes. `abiCheck` gate is part of `check`.
- **Branch protection:** `main` has protected branch rules — never push directly. Use the `scripts/release.sh` script to automate the branch → PR → merge → tag flow.
- Security advisories are reported via `SECURITY.md`.

<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project are documented in this file.

Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support for [0.1.0 release](https://github.com/trancee/MeshLink-crypto/releases/tag/v0.1.0)

## [0.1.0] — 2026-08-15

Initial release. All seven RFC-standard primitives with constant-time pure-K
implementations and per-primitive native fallback:

- SHA-256 / SHA-512 (RFC 6234)
- HMAC-SHA256 (RFC 2104)
- HKDF-SHA256 (RFC 5869)
- X25519 (RFC 7748)
- Ed25519 (RFC 8032)
- ChaCha20-Poly1305 (RFC 8439)

### Added

- Initial snapshot with all seven RFC-standard primitives
- Maven Central publishing configuration (`maven-publish` + `signing` plugins)
- Gradle version catalog version property (`libs.versions.library`)
- `.github/workflows/publish.yml` — release workflow targeting Maven Central
- `.env.example` — template for local Maven Central + GPG signing credentials
- DispatchVerificationTest in `commonTest` — RFC KAT dispatch verification via public API
- PureKFallbackVerificationTest in `commonTest` — RFC KAT verification of PureK implementations directly, independent of dispatch layer
- markdownlint-cli2 + lychee link checker (`scripts/check-markdown.sh`, `.markdownlint-cli2.jsonc`, `lychee.toml`)
- yamllint configuration (`.yamllint`) for YAML syntax enforcement
- gitleaks secret scanning (`.gitleaks.toml`) with allowlist for vendored test vectors
- Git hooks: `commit-msg` (Conventional Commits), `pre-commit` (fast tier), `pre-push` (full verification tier)
- CI `lint` job with gitleaks, yamllint, and markdownlint+lychee
- `github-actions` ecosystem in Dependabot configuration

### Changed

- CI `android-matrix` job now verifies `compileAndroidMain` only (compile-time verification across SDK 21/28/29/37) — removed misleading `jvmTest` runs that showed identical JCA-dispatch results regardless of compileSdk
- Removed `android-emulator` CI job: KMP AGP 9.x does not auto-create `androidInstrumentedTest` source set or `androidConnectedCheck` task; emulator used `arm64-v8a` system image on `ubuntu-latest` (x86_64)
- `scripts/ci-summary.py` dispatch table now shows native, PureK, and simulated-fallback test results; platform label includes compileSdk level (e.g. "JVM [JDK 21] / compileSdk=21"); added transparent SDK-level dispatch notes explaining that matrix jobs verify compilation only and tests run on JVM/JDK 21
- macOS `build` job: `html { onCheck }` reads `koverHtmlOnCheck` property (default `true`); CI sets it to `false` to skip HTML report generation on CI
- Gradle wrapper `--rerun` corrected to `--rerun-tasks` across all docs and hooks (Gradle 9.x compatibility)

### Fixed

- `TimingHarnessTest` "constant-time operation" test no longer fails spuriously on CI — increased iterations to 100_000 and warmup to 10_000 so per-sample durations reach millisecond scale where `System.nanoTime()` measurement is stable; added zero-median guard in `assertConstantTime` to prevent NaN/Infinity from sub-nanosecond truncation
- `.gitignore` now excludes `.env` and `.env.*` — prevents credential leaks
- CODEOWNERS now points to `/crypto/src/` instead of the non-existent `/meshlink/src/`
- CI uses `platforms;android-37.0` (not `platforms;android-37`) for SDK installation
- GitHub Actions deprecated Node.js 20 — all actions upgraded to v4/v5 (checkout@v5, setup-java@v5, setup-android@v4, cache@v5)
- `actions/setup-android@v3` invalid inputs (`api-level`/`build-tools`) — upgraded to `@v4` with direct `sdkmanager` calls
- `scripts/ci-summary.py` markdown tables rendered with blank rows between rows — fixed table rendering
- All markdownlint violations resolved (MD024 duplicate headings, MD029 ordered list, MD056 table column count, MD031 fence state, MD041 first heading)
- Broken external link in `docs/adr/0008-skie-excluded.md`: `https://skie.kotlinlang.org` → `https://skie.co`
- YAML syntax and line-length issues in GitHub issue templates fixed

[Unreleased]: https://github.com/trancee/MeshLink-crypto/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/trancee/MeshLink-crypto/releases/tag/v0.1.0

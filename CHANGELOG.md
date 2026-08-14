# Changelog

All notable changes to this project are documented in this file.

Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Maven Central publishing configuration (`maven-publish` + `signing` plugins)
- Gradle version catalog version property (`libs.versions.library`)
- `.github/workflows/publish.yml` — release workflow targeting Maven Central
- `.env.example` — template for local Maven Central + GPG signing credentials
- DispatchVerificationTest in `commonTest` — RFC KAT dispatch verification via public API
- PureKFallbackVerificationTest in `commonTest` — RFC KAT verification of PureK implementations directly, independent of dispatch layer
### Changed
- CI `android-matrix` job now verifies `compileAndroidMain` only (compile-time verification across SDK 21/28/29/37) — removed misleading `jvmTest` runs that showed identical JCA-dispatch results regardless of compileSdk
- Removed `android-emulator` CI job: KMP AGP 9.x does not auto-create `androidInstrumentedTest` source set or `androidConnectedCheck` task; emulator used `arm64-v8a` system image on `ubuntu-latest` (x86_64)
- `scripts/ci-summary.py` dispatch table now shows native, PureK, and simulated-fallback test results; platform label includes compileSdk level (e.g. "JVM [JDK 21] / compileSdk=21"); added transparent SDK-level dispatch notes explaining that matrix jobs verify compilation only and tests run on JVM/JDK 21
- macOS `build` job: `html { onCheck }` reads `koverHtmlOnCheck` property (default `true`); CI sets it to `false` to skip HTML report generation on CI
### Fixed
- `.gitignore` now excludes `.env` and `.env.*` — prevents credential leaks
- CODEOWNERS now points to `/crypto/src/` instead of the non-existent `/meshlink/src/`
- CI uses `platforms;android-37.0` (not `platforms;android-37`) for SDK installation
- GitHub Actions deprecated Node.js 20 — all actions upgraded to v4/v5 (checkout@v5, setup-java@v5, setup-android@v4, cache@v5)
- `actions/setup-android@v3` invalid inputs (`api-level`/`build-tools`) — upgraded to `@v4` with direct `sdkmanager` calls
- `scripts/ci-summary.py` markdown tables rendered with blank rows between rows — fixed table rendering

## [0.1.0-SNAPSHOT] — pre-release

Initial snapshot. All seven RFC-standard primitives with constant-time pure-K
implementations and per-primitive native fallback:

- SHA-256 / SHA-512 (RFC 6234)
- HMAC-SHA256 (RFC 2104)
- HKDF-SHA256 (RFC 5869)
- X25519 (RFC 7748)
- Ed25519 (RFC 8032)
- ChaCha20-Poly1305 (RFC 8439)
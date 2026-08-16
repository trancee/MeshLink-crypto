<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project are documented in this file.

Format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Artifact coordinates changed from `ch.trancee.meshlink:crypto` to
  `ch.trancee.meshlink:meshlink-crypto` (main metadata publication).
  Platform-specific publications renamed:
  - `crypto-android` → `meshlink-crypto-android`
  - `crypto-jvm` → `meshlink-crypto-jvm`
  - `crypto-iosarm64` → `meshlink-crypto-ios`
  - `crypto-iosSimulatorArm64` → dropped (only `iosArm64` device binary needed for
    distribution; simulator builds are a local development concern)
- Publishing transfer namespace changed from `ch.trancee.meshlink` to
  `ch.trancee.meshlink.crypto` in `.github/workflows/publish.yml` — the Central
  Portal deployment now appears under the `ch.trancee.meshlink.crypto` namespace.
  Note: the Maven `group` in `crypto/build.gradle.kts` remains
  `ch.trancee.meshlink` (the staging profile is `ch.trancee`, the account root,
  and cannot be overridden via code).
- `SIGNING_KEY_ID` env var is no longer consumed by the build — the signing
  plugin extracts the key ID from the PGP private key block automatically.
  The secret can be removed from GitHub without affecting the build.
- Migrated publishing from the legacy OSSRH Staging API (`ossrh-staging-api.central.sonatype.com`) to the Central Portal Publisher API (`central.sonatype.com/api/v1/publisher/upload`) via bundle upload. The `publish.yml` workflow now builds, signs, and zips artifacts to a local file repository, then uploads the bundle with a Bearer token (Central Portal User Token).
- Replaced the remote publishing repository in `crypto/build.gradle.kts` with a local file repository (`build/maven-bundle/`). The `centralBundle` Zip task packages this directory for upload.
- Replaced the fragile `useInMemoryPgpKeys()` block (with 6-line key normalization) in `crypto/build.gradle.kts` with the standard `signingInMemoryKey` / `signingInMemoryKeyPassword` Gradle properties, which the signing plugin reads automatically from `ORG_GRADLE_PROJECT_*` env vars.
- Added `sourcesJarJvm`, `sourcesJarAndroid`, and `centralBundle` Gradle tasks. Sources JARs are attached to the JVM and Android publications — required by the Central Portal alongside javadoc JARs and PGP signatures.
- Removed `SIGNING_KEY_ID` from `.env.example` — the signing plugin extracts the key ID from the PGP key block automatically.
- Rewrote `.github/workflows/publish.yml`: removed the PGP key validation, OSSRH credential check, stale staging repository drop, staging search, manual transfer (`POST /manual/upload/defaultRepository/<namespace>`), and post-transfer verification steps. Replaced with the Central Portal Publisher API flow: upload → poll status → publish deployment.
- Fixed `--rerun` → `--rerun-tasks` across AGENTS.md, CONTRIBUTING.md, README.md, CONSTITUTION.md, and kotlin-polyglot-test-analysis SKILL.md (Gradle 9.x requires `--rerun-tasks`, not `--rerun`).

### Fixed

- Publishing yamllint failure: Python heredoc inside YAML block scalar
  broke YAML parsing; single-line `python3 -c` alternative was 192 chars
  (exceeds 120-char yamllint limit). Replaced with `jq` for staging repo
  parsing in the "Drop stale staging repositories" step.
- Publishing `402 Payment Required` from `s01.oss.sonatype.org`: the Sonatype
  account has migrated to the Central Portal. Migrated publishing repository URL
  to `https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/`
  (Central Portal OSSRH Staging API compatibility endpoint). Added credential
  diagnostic step that tests against the new endpoint and identifies 401
  (credentials are legacy OSSRH tokens — need Central Portal User Token) vs
  other errors. Added post-upload `POST /manual/upload/defaultRepository/<namespace>`
  transfer step required by the Central Portal to make staged deployments visible.
  Added post-transfer verification step that queries the staging API to confirm
  the deployment was accepted (state changes to "closed", `portal_deployment_id`
  becomes non-null).
- `Task 'PGP' not found` CI error: the `useInMemoryPgpKeys()` call with a `null` key ID was incompatible with the signing plugin. Resolved by switching to property-based `signingInMemoryKey` / `signingInMemoryKeyPassword`.
- `Javadocs must be provided but not found in entries` Central Portal validation error: javadoc JAR was not reliably attached when using the OSSRH Staging API. Now properly wired via `artifact(tasks.named("javadocJarJvm"))` in the local file repository flow.
- Namespace mismatch (`ch.trancee.meshlink` Maven group vs `ch.trancee.meshlink.crypto` transfer namespace): eliminated by the Central Portal Publisher API, which derives the namespace from the authenticated token.
- `publish.yml` build step now runs `./gradlew :crypto:check` (quality gate) before `:crypto:publish :crypto:centralBundle`, with `--rerun-tasks --no-build-cache` flags on all Gradle invocations.
- PGP key parsing failure (`no valid OpenPGP data found` / `Could not read PGP secret key`): the `SIGNING_KEY` secret contained literal `\\n` (double-backslash-n) escape sequences instead of actual newlines. Added normalization in `crypto/build.gradle.kts` that replaces `\\n` → LF before passing the key to `useInMemoryPgpKeys()`. Also updated the GitHub secret and `.env` to use proper newline formatting.
- `publish.yml` upload step `jq` parse error: Central Portal returns the deployment ID as a plain-text UUID, not JSON `{deploymentId: "..."}`. Replaced `jq -r '.deploymentId'` with `curl -o file -w '%{http_code}'` + `tr -d '[:space:]'`.
- macOS portability: `head -n -1` (BSD head) fails with "illegal line count -- -1" on GitHub Actions `macos-latest`. Replaced with portable `curl -o /tmp/file -w '%{http_code}'` pattern.
- Validation step shell syntax error: a missing `fi` caused "unexpected end of file" on macOS runners.

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

- Publish workflow signing failure: multi-line GPG key block (SIGNING_KEY)
  broke shell expansion when passed via `-P` flags — signing config now passed
  exclusively via environment variables
- Signing key ID format validation: Gradle signing plugin rejects GPG
  fingerprints — build config passes `null` keyId and lets the plugin extract
  the key ID from the PGP key itself
- PGP key normalization in signing block: normalizes CRLF→LF, converts
  literal `\\n` escape sequences to real newlines, and auto-wraps key with
  PGP ASCII armor headers if missing
- Restored `sign(publishing.publications)` call that was accidentally dropped
  during the key normalization edit — without it, no signing tasks were
  created and artifacts were uploaded unsigned
- Publish workflow: added PGP key validation step that tries parsing the
  key as-is, with headers added, and with newline conversion; fails fast
  if the key is invalid
- `actions/checkout` upgraded from @v5 to @v7 across all workflows
- `TimingHarnessTest` "constant-time operation" test no longer fails spuriously on CI — increased iterations to 100_000 and warmup to 10_000 so per-sample durations reach millisecond scale where `System.nanoTime()` measurement is stable; added zero-median guard in `assertConstantTime` to prevent NaN/Infinity from sub-nanosecond truncation
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

# Copilot Instructions — MeshLink-crypto

This file guides AI agents (GitHub Copilot, CodePilot, etc.) on the conventions,
patterns, and workflows specific to this repository. For the authoritative
project overview and agent workflow, see [AGENTS.md](../AGENTS.md).

---

## Project at a Glance

A pure-Kotlin, constant-time cryptography library for Kotlin Multiplatform.
Targets: JVM, Android (API 21+), iOS arm64 + simulator. JS/WASM out of scope.

- **Kotlin** 2.4.10 (pinned in `gradle/libs.versions.toml`)
- **JDK** 21 (`jvmToolchain(21)`)
- **AGP** 9.3.1 (`com.android.kotlin.multiplatform.library`)
- **Build tool** Gradle 9.7.0 (wrapper)
- **Format** ktfmt (Google style)
- **Lint** detekt 2.0.0-alpha.6 (includes custom `ConstantTimeRule`)
- **Coverage** kover 0.9.9 (100% on pure-K path)
- **ABI check** KGP built-in `kotlin { abiValidation {} }`

---

## Language-Specific Conventions

### Kotlin

- **Code style**: `kotlin.code.style=official` in `gradle.properties`.
  ktfmt is the formatting authority. Run `./gradlew spotlessKotlinApply` to
  auto-format. The pre-commit hook surfaces formatting failures as a warning
  (surf, not a hard block).
- **Explicit API**: all public declarations in `:crypto` use `public` modifier
  explicitly. Internal dispatch objects (`expect`/`actual`) are `internal`.
- **No `BigInteger`** in any pure-K path (ADR-0001). Curve operations use the
  radix-2^26 field engine (`FieldElement`). Hash/MAC/AEAD use fixed-round
  32-bit/64-bit word arithmetic.
- **`Result<T>` returns**: all public API methods return `Result<T>` (no
  exceptions crossing the KMP boundary). Callers use `.getOrThrow()`.
- **`Closeable` key handles**: `SecretKey`, `PrivateKey`, `PublicKey` are
  `Closeable` and zero their backing arrays on `close()`. Always use
  `use { ... }` or call `close()` explicitly.
- **`@Secret` annotation**: annotate all secret parameters (`key`, `nonce`,
  `hash state`) with `@Secret`. The `ConstantTimeRule` bans data-dependent
  branches and secret-indexed array access on annotated parameters.
- **`--rerun --no-build-cache`**: every `./gradlew` invocation must include
  these flags (see `docs/agents/build.md`).

### Gradle / Kotlin DSL

- Version catalog lives in `gradle/libs.versions.toml`. Never hardcode versions
  in build scripts.
- Plugins are applied per-module, not at the root. The root
  `build.gradle.kts` is intentionally empty.
- Kotlin DSL (`.kts`) files are spotless-formatted with ktfmt.

### Git

- **Commits**: Conventional Commits (`feat:`, `fix:`, `chore:`, etc.).
- **PR titles**: Must also use Conventional Commit format.
- **Branch**: always create a feature branch; never commit directly to `main`.
- **Git hooks**: install once per clone with
  `git config core.hooksPath .githooks`. The pre-commit hook runs
  `spotlessCheck` (ktfmt) on changed Kotlin files.

---

## Test Conventions

- **Test runner**: JUnit 5 (JUnit Platform) on JVM. `commonTest` uses
  `kotlin.test` for multiplatform assertions.
- **Test location**: `crypto/src/jvmTest/` for JVM-specific tests,
  `crypto/src/commonTest/` for cross-platform harness tests.
- **Test tags** (`@Tag`):
  | Tag | Purpose |
  |-----|---------|
  | `positive` | Correctness assertions (known-answer tests, Wycheproof vectors) |
  | `critical-path` | Core primitive correctness |
  | `timing` | Timing variance assertions (opt-in) |
  | `security` | Security-related assertions |
  | `smoke` | Basic build/toolchain validation |
- **Wycheproof vectors**: placed in `crypto/src/jvmTest/resources/wycheproof/`.
- **Known-answer tests**: inline test functions for primitives without a
  Wycheproof corpus.
- **Coverage gate**: `kover` enforces 100% line + branch coverage on the
  pure-K path. The native-fallback dispatch classes are excluded from the gate
  (they contain no secret-handling logic).

---

## Code Style Notes

- ktfmt (Google style) is the single source of truth for formatting and naming.
- detekt 2.0.0-alpha.6 handles static analysis and the custom
  `ConstantTimeRule` (see `crypto-detekt-rules/src/`).
- The detekt baseline files (`detekt-baseline-*.xml`) are checked in; do not
  delete or modify them unless you are resolving a specific violation.
- Spotless runs ktfmt on `src/**/*.kt` and `*.kts` files.

---

## Conventions Mined from PR Reviews

This is a solo-maintainer repository (trancee). PRs are authored and merged
by the same developer, so formal PR review comments are absent. The
conventions below are derived from the commit history, the contribution
checklist, and the architecture decisions (ADRs):

1. **Every primitive must ship with correctness vectors** (Wycheproof or
   RFC known-answer tests) — never merge a primitive without tests.
2. **Constant-time lint must be green** on the pure-K path — detekt's
   `ConstantTimeRule` catches `@Secret` violations at compile time.
3. **100% coverage on the pure-K path** — kover's `minBound(100)` gate
   must pass.
4. **ABI must be validated** — `abiValidation {}` must pass; no accidental
   public API changes.
5. **New primitives follow the registration chain** — see "Adding a New
   Primitive" below. Every step is required, no shortcuts.
6. **Conventional Commits** on all PR titles and commit messages.
7. **`--rerun --no-build-cache`** on every Gradle invocation.

---

## Maintenance Matrix

This matrix traces what must be updated when different parts of the codebase
change. It is the change-cascade map for the repo.

### Adding a New Primitive (RFC-standard)

Following `docs/how-to/add-primitive.md`, the full registration chain is:

| Step | File(s) to modify | What to do |
|------|-------------------|------------|
| 1 | GitHub issue | Open an issue with the acceptance checklist from `docs/agents/issue-tracker.md` |
| 2 | `crypto/src/commonMain/kotlin/.../Foo.kt` | Write the pure-K implementation. Name the object `FooPureK`. Annotate secret params `@Secret`. No `BigInteger`. Use `cswap` for conditional selection. Use bitwise-OR accumulator for tag comparison. |
| 3 | `crypto/src/commonMain/kotlin/.../ExpectDeclarations.kt` | Add `internal expect object Foo` with the dispatch signature. |
| 4a | `crypto/src/jvmMain/kotlin/.../Foo.kt` | `actual object Foo` delegating via `fooNative() ?: FooPureK.compute()` |
| 4b | `crypto/src/androidMain/kotlin/.../Foo.kt` | Same pattern (KMP source sets do not inherit across targets) |
| 4c | `crypto/src/iosMain/kotlin/.../Foo.kt` | Same pattern (CommonCrypto / Security.framework via cinterop) |
| 5 | `crypto/src/{jvmMain,androidMain,iosMain}/kotlin/.../CryptoBridge.kt` | Add `fooNative()` dispatch function. Bridge files must NOT contain `@Secret` params. |
| 6 | `crypto/src/commonMain/kotlin/.../CryptoFacade.kt` or `Crypto.kt` | Add the public entry point (`FooBar` object or `Crypto.foo()` method). Returns `Result<T>`. |
| 7 | `crypto/src/commonMain/kotlin/.../CryptoProvider.kt` | If the primitive supports native provider injection, add `supportsFoo()` + `foo()` to the `CryptoProvider` interface. |
| 8a | `crypto/src/jvmTest/resources/wycheproof/` | Add Wycheproof test vector JSON if a corpus exists. |
| 8b | `crypto/src/jvmTest/kotlin/.../FooTest.kt` | Write known-answer tests. Tag with `@Tag("positive")` and `@Tag("critical-path")`. |
| 9 | `crypto/detekt-baseline-*.xml` | Regenerate if new detekt findings appear (only if they are intentional and approved). |
| 10 | ABI dump (`.api` file) | Run `./gradlew :crypto:apiDump` and commit the updated dump. The `abiValidation {}` gate checks this in CI. |
| 11 | `CHANGELOG.md` | Add entry under `[Unreleased]` → `### Added`. |
| 12 | `docs/how-to/add-primitive.md` | Update if the registration chain has changed. |
| 13 | `docs/reference/api-reference.md` | Add the new public API to the reference. |
| 14 | `docs/reference/supported-primitives.md` | Add a row to the primitives table. |

### Changing a Public API

When you add, remove, or change a public method in `crypto/src/commonMain/`:

| File(s) | What to do |
|---------|------------|
| ABI `.api` dump | Run `./gradlew :crypto:apiDump` to regenerate. Commit the diff. |
| `crypto/build.gradle.kts` | If the new public class is a dispatch object that delegates (not pure-K), add it to the kover `excludes` list. |
| `CHANGELOG.md` | Add entry under `[Unreleased]`. |
| `docs/reference/api-reference.md` | Update the API reference. |

### Changing Documentation

| Trigger | Files to update |
|---------|-----------------|
| Docs content change | The changed file + `AGENTS.md` if structure changed |
| New ADR | `docs/adr/` + `README.md` ADR section + `docs/explanation/architecture.md` related-reading list |
| New how-to guide | `README.md` documentation section link |
| New primitive | `docs/reference/supported-primitives.md` + `docs/reference/api-reference.md` |

### Changing Build Configuration

| Trigger | Files to update |
|---------|-----------------|
| Version bump (Kotlin/AGP/detekt/kover) | `gradle/libs.versions.toml` + `docs/agents/build.md` if Kotlin version is mentioned + `README.md` if version is mentioned |
| New detekt rule | `crypto-detekt-rules/src/` + `crypto/detekt.yml` config |
| New Gradle property | `gradle.properties` + `.env.example` if credentials-related |

### CI / Release Workflow Changes

| Trigger | Files to update |
|---------|-----------------|
| CI workflow change | `.github/workflows/ci.yml` + `CONSTITUTION.md` §4 if gates change |
| Publish workflow change | `.github/workflows/publish.yml` + `CONSTITUTION.md` §5 + `CHANGELOG.md` |
| New secrets needed | `.env.example` (template) — never commit `.env` |

---

## CI / Release

- **CI workflow**: `.github/workflows/ci.yml` runs on every PR. Two jobs:
  1. `build` on `macos-latest` — runs `./gradlew check --parallel` (detekt +
     kover + spotless + abiValidation + JVM tests + iOS simulator tests).
     Sets `ORG_GRADLE_PROJECT_koverHtmlOnCheck=false` to skip HTML report on CI.
  2. `android-matrix` on `ubuntu-latest` — verifies `compileAndroidMain`
     across compileSdk 21/28/29/37. Tests run on JVM/JDK 21, not on Android.
- **Publish workflow**: `.github/workflows/publish.yml` runs on `v*` tags.
  Publishes to Maven Central with GPG signing. Requires secrets:
  `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `SIGNING_KEY_ID`,
  `SIGNING_KEY`, `SIGNING_KEY_PASSWORD`.
- **CI summary**: `scripts/ci-summary.py` generates an inline test/coverage
  summary in the Actions run summary (no artifact download needed).

---

## Useful Commands

| Goal | Command |
|------|---------|
| Full quality gate (local) | `./gradlew check --rerun --no-build-cache` |
| Format Kotlin | `./gradlew spotlessKotlinApply` |
| Detekt (constant-time lint) | `./gradlew :crypto:detektCommonMainSourceSet --rerun --no-build-cache` |
| Coverage report | `./gradlew :crypto:koverXmlReport --rerun --no-build-cache` |
| ABI dump | `./gradlew :crypto:apiDump --rerun --no-build-cache` |
| Run tests only | `./gradlew test --rerun --no-build-cache` |
| iOS test (Mac only) | `./gradlew :crypto:iosSimulatorArm64Test --rerun --no-build-cache` |
| Local Maven publish | `./gradlew :crypto:publishToMavenLocal --rerun --no-build-cache` |

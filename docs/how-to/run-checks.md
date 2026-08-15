# How to: Run Tests and Quality Gates

> **How-to guide.** This guide shows you how to run the build, test suite, and quality gates locally. It assumes you have the prerequisites installed (JDK 21, Android SDK, Xcode on macOS). For contributing a change, see the [Add a Primitive](add-primitive.md) guide.

## Prerequisites

- JDK 21 (pinned at `jvmToolchain(21)`)
- Android SDK — set `ANDROID_HOME` or `ANDROID_SDK_ROOT`
- A Mac with Xcode — required for iOS targets (they do not compile on non-Mac hosts)

Install git hooks once per clone:

```bash
git config core.hooksPath .githooks
```

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

## Run the full quality gate

From the repository root, always pass `--rerun-tasks` and `--no-build-cache`:

```bash
./gradlew check --rerun-tasks --no-build-cache
```

This runs:

- **ktfmt** — Kotlin code formatting
- **detekt** — static analysis, including the custom `ConstantTimeRule` (ADR-0003)
- **kover** — test coverage (100% on the pure-Kotlin path)
- **abiValidation** — Kotlin ABI dump check
- **Tests** — JUnit 5 test suite with Wycheproof and known-answer vectors

## Run tests only

```bash
./gradlew test --rerun-tasks --no-build-cache
```

Tests live in `crypto/src/jvmTest/`. They use JUnit 5 with `@Tag` annotations. Tags include:

| Tag | Purpose |
|---|---|
| `positive` | Correctness assertions (known-answer tests, Wycheproof vectors) |
| `critical-path` | Core primitive correctness |
| `timing` | Timing variance assertions (opt-in, ADR-0003) |
| `security` | Security-related assertions |
| `smoke` | Basic build/toolchain validation |

## Run the constant-time lint only

```bash
./gradlew :crypto:detektCommonMainSourceSet --rerun-tasks --no-build-cache
```

This runs the `ConstantTimeRule` on `commonMain`. It flags any data-dependent branch or secret-indexed access in `@Secret`-annotated code.

## Run coverage only

```bash
./gradlew :crypto:koverXmlReport --rerun-tasks --no-build-cache
```

The HTML report is at `crypto/build/reports/kover/report.html`. The gate enforces 100% line and branch coverage on the pure-Kotlin path.

## CI

CI runs on `macos-latest` and executes `./gradlew check` on every pull request. See `.github/workflows/ci.yml`.

# Build & Test Conventions

## Gradle invocations

Every `./gradlew` call **must** include `--rerun-tasks` and `--no-build-cache` to ensure fresh execution. Do not rely on cached outputs.

```bash
./gradlew test --rerun-tasks --no-build-cache
```

## Project layout

- Single KMP module: `:crypto` (see ADR-0006).
- Root `build.gradle.kts` is intentionally empty — plugins are applied per-module via the version catalog (`gradle/libs.versions.toml`).

## Lint, format, and coverage

Per ADR-0007, the verification toolchain is:

- **ktfmt** — Kotlin code formatting
- **detekt** — static analysis, including constant-time lint
- **kover** — test coverage (100% coverage on the pure-K path)

## Kotlin version

Use Kotlin 2.4.10 (latest stable KMP). No legacy toolchains.

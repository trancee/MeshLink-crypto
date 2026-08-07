# Build & Test Conventions

## Gradle invocations

Every `./gradlew` call **must** include `--rerun` and `--no-build-cache` to ensure fresh execution. Do not rely on cached outputs.

```bash
./gradlew test --rerun --no-build-cache
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

## Benchmarking

JMH microbenchmarks live in `crypto/src/jvmBenchmark/` and are configured via the
`benchmark {}` extension in `crypto/build.gradle.kts`. The `kotlinx-benchmark` plugin
provides the `jvmBenchmarkBenchmark` task (JMH-backed, JSON config — do **not** pass
JMH CLI args via `--args`, the plugin handles them).

```bash
# Run all benchmarks (warms up + measures per the config: 2 warmup + 3 measure iters)
./gradlew :crypto:jvmBenchmarkBenchmark --rerun --no-build-cache
```

Benchmark dependencies are dev-only (see ADR-0005): `kotlinx-benchmark-runtime` is
declared on the `jvmBenchmark` source set only, never on `commonMain`.

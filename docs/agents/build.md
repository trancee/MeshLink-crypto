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

### Before/after comparison

ADR-0009 requires a before/after benchmark comparison for any code change to a
pure-K crypto primitive. The JVM is not deterministic. Run the comparison on a
quiet host, not a CI runner.

Steps:

1. **Capture the baseline.** On the before-change revision, run the benchmark
   and save the output.
   ```bash
   # On the BEFORE revision:
   ./gradlew :crypto:jvmBenchmarkBenchmark --rerun --no-build-cache \
     --quiet > bench-before.txt 2>&1
   ```
2. **Apply the change.** Edit the primitive code (the pure-K path).
3. **Capture the after.** On the after-change revision, run the same command.
   ```bash
   # On the AFTER revision:
   ./gradlew :crypto:jvmBenchmarkBenchmark --rerun --no-build-cache \
     --quiet > bench-after.txt 2>&1
   ```
4. **Compare.** Compare mean ns/op and ops/s for each benchmark. A regression of
   more than 10% on any path blocks merge. An improvement of any size is accepted.
5. **Scope.** Native-fallback-only changes where the pure-K path is unchanged are
   exempt. The benchmark must still exist for the primitive.

**Noise discipline.** Close other applications. Run twice. Compare the two
runs. Treat small deltas as noise unless they repeat. The committed benchmark
source lets CI replay any disputed regression at will.

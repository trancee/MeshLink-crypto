# Contributing to MeshLink-crypto

A Kotlin Multiplatform crypto library with constant-time pure-Kotlin primitives.
Before you start, read `CONTEXT.md` (domain glossary) and an ADR in `docs/adr/`.

## Prerequisites

- JDK 21 — the toolchain is pinned at `jvmToolchain(21)`.
- Android SDK — the KMP plugin configures the Android target for every Gradle
  task, so even a JVM-only task needs it. Set `ANDROID_HOME` or `ANDROID_SDK_ROOT`.
- A Mac with Xcode — the iOS targets are part of the project graph. They do not
  compile on non-Mac hosts. CI builds on `macos-latest`.

## Build, test, and check

Run from the repo root. Always pass `--rerun --no-build-cache` so no cached output
hides a breakage (`docs/agents/build.md`).

```bash
# Full gate: ktfmt + detekt (constant-time lint) + kover (100% pure-K) + ABI + tests
./gradlew check --rerun --no-build-cache
```

## Benchmarks

JMH microbenchmarks live in `crypto/src/jvmBenchmark/`. Run them with:

```bash
./gradlew :crypto:jvmBenchmarkBenchmark --rerun --no-build-cache
```

Any code change to a pure-K crypto primitive must pass a before/after benchmark
comparison (ADR-0009). See `docs/agents/build.md` for the capture-and-compare steps.
A regression of more than 10% on any path blocks merge.

## Git hooks

The repo keeps git hooks in `/.githooks/`. Install them, one time, per clone:

```bash
git config core.hooksPath .githooks
```

The `pre-commit` hook runs the ADR-0009 before/after benchmark comparison
automatically when a commit stages a file under
`crypto/src/commonMain/kotlin/ch/trancee/meshlink/crypto/`. It surfaces a diff of
the before/after JMH output. It does not hard-block — the JVM is
non-deterministic, so small deltas are noise, not defects. Skip it with
`SKIP_BENCH_HOOK=1 git commit ...`, or `git commit --no-verify`.

## Contributing a crypto primitive

Open a GitHub issue first. Carry the crypto-primitive acceptance checklist
(`docs/agents/issue-tracker.md`): correctness vectors, a JMH benchmark, green
constant-time lint, and 100% kover on the pure-K path. A primitive is not done
without its benchmark (ADR-0009).

## Pull requests

- Conventional Commits.
- Ensure `./gradlew check --rerun --no-build-cache` is green.
- CI runs on every pull request (`.github/workflows/ci.yml`, macOS + Android + iOS).

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

## Git hooks

The repo keeps git hooks in `/.githooks/`. Install them, one time, per clone:

```bash
git config core.hooksPath .githooks
```


## Pull requests

- Conventional Commits.
- Ensure `./gradlew check --rerun --no-build-cache` is green.
- CI runs on every pull request (`.github/workflows/ci.yml`, macOS + Android + iOS).

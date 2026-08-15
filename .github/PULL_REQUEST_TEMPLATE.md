## Description

<!-- What does this PR change? Link to the issue it resolves or the ADR it implements. -->

## Changes

<!-- Summarize the changes. For new primitives, list each file touched. -->

- 

## How to Test

<!-- 
For crypto primitives, verify:
1. Correctness vectors pass (Wycheproof + RFC KAT).
2. `./gradlew check --rerun --no-build-cache` is green locally.
3. Constant-time lint is clean: `./gradlew :crypto:detektCommonMainSourceSet --rerun --no-build-cache`
4. ABI is clean: `./gradlew :crypto:apiCheck --rerun --no-build-cache`
-->

```bash
./gradlew check --rerun --no-build-cache
```

## Checklist

- [ ] Conventional Commit title (matches PR title)
- [ ] `./gradlew check --rerun --no-build-cache` passes locally
- [ ] detekt constant-time lint is clean on the pure-K path
- [ ] kover 100% coverage on the pure-K path
- [ ] `abiCheck` / `abiValidation` is clean (or `.api` dump updated and committed)
- [ ] README.md and/or affected docs updated (if user-facing)
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] Git hooks installed: `git config core.hooksPath .githooks`

Assisted by [ai-ready](https://github.com/johnpapa/ai-ready)

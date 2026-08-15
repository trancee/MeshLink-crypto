# Verification gates: Wycheproof + constant-time lint + test harness

## Status

accepted

## Context

The pure-Kotlin path is the only code that holds secrets and is authored by us; the native fallback path is inherited-trust. Correctness and constant-time guarantees must therefore be enforced on the pure-K path, while the native path must at least be exercised by the target matrix so a missing native primitive is caught.

## Decision

The pure-K path must pass three gates:

1. **Wycheproof** test vectors for every primitive as the correctness oracle.
2. A **static lint** that bans data-dependent branching (`if`/conditional) and secret-dependent indexing (`array[i]` with a secret index) in secret-data scopes.
3. A **Wycheproof-routed timing test harness** that asserts no early-exit (e.g. comparisons must be constant-time, never `contentEquals()` or index-on-first-mismatch).

The native-fallback path is not held to the lint (inherited-trust), but presence/absence of each native primitive is covered by the target-matrix tests so the pure-K path is always reached.

## Consequences

- Real alternative "native-trust-only" was rejected: the pure-K path is the whole point of this library.
- "Manual review instead of lint" was rejected: lint is automatable, reviewable, and enforced in CI.

## Corroborating research

KMP security best practice (see `research/crypto-kmp-security-research.md`) extends gate 3: in addition to the static lint and the Wycheproof-routed harness, **per-target instrumentation** — Android Systrace, iOS Instruments — is the recommended way to *confirm* constant-time execution of the pure-K path on each target. The harness should therefore be per-target and include a timing-variance assertion, not a single-JVM timing test.

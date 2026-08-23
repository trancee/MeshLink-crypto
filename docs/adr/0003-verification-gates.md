# Verification gates: Wycheproof + constant-time lint + test harness

## Status

accepted

## Context

The pure-Kotlin path is the only code that holds secrets and is authored by us; the native fallback path is inherited-trust. Correctness and constant-time guarantees must therefore be enforced on the pure-K path, while the native path must at least be exercised by the target matrix so a missing native primitive is caught.

## Decision

The pure-K path must pass three gates:

1. **Wycheproof** test vectors for every primitive as the correctness oracle. For primitives without a Wycheproof corpus (SHAKE128, SHAKE256), [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) known-answer test vectors from [FIPS 202 §D.4/D.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) serve as the correctness oracle, supplemented by additional vectors computed via Python's [`hashlib.shake_128`/`shake_256`](https://docs.python.org/3/library/hashlib.html) (FIPS 202-compliant reference implementation producing byte-identical CAVP output). Keccak-f[1600] round constants are verified against the [XKCP/Keccak Team](https://github.com/XKCP/XKCP) reference (`TweetableFIPS202.c`, `keccak_specs_summary.html`); parameters match XKCP's `SimpleFIPS202.c` exactly (SHAKE128 rate=1344/capacity=256/suffix=0x1F; SHAKE256 rate=1088/capacity=512/suffix=0x1F).

## Consequences

- Real alternative "native-trust-only" was rejected: the pure-K path is the whole point of this library.
- "Manual review instead of lint" was rejected: lint is automatable, reviewable, and enforced in CI.

## Corroborating research

KMP security best practice (see `research/crypto-kmp-security-research.md`) extends gate 3: in addition to the static lint and the Wycheproof-routed harness, **per-target instrumentation** — Android Systrace, iOS Instruments — is the recommended way to *confirm* constant-time execution of the pure-K path on each target. The harness should therefore be per-target and include a timing-variance assertion, not a single-JVM timing test.

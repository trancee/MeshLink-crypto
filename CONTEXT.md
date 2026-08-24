# crypto-kmp

A Kotlin Multiplatform cryptography library: pure-Kotlin, constant-time implementations of [RFC](https://datatracker.ietf.org)/[FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)-standard primitives, with fallback to a target's native crypto provider when available. Spec texts live in `docs/rfcs/`; test vectors come from [Wycheproof](https://github.com/google/wycheproof) (for primitives with a corpus) and [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) known-answer tests (FIPS 202 §D.4/D.5 for SHAKE128/SHAKE256, which lack a Wycheproof corpus, cross-checked against [Python `hashlib`](https://docs.python.org/3/library/hashlib.html)).

## Language

**constant-time**: Execution time is independent of the processed data — no data-dependent branching and no data-dependent memory access. (The mechanics — 10-limb radix-2^26 field arithmetic, `cswap`, no `BigInteger` — are recorded in ADR-0001.)

**pure Kotlin**: An implementation with zero external dependencies that compiles for every KMP target. _Avoid_: `java.security`, `javax.crypto`, BouncyCastle, any native binding that pulls a dependency. (This term governs the **pure-K path only**; the native-fallback path may use the modern platform provider — see Fallback.)

**Wycheproof**: [Google's](https://github.com/google/wycheproof) cryptographic test-vector corpus, used as the correctness oracle for primitives with a corpus. Primitives without a Wycheproof corpus (SHAKE128, SHAKE256) use [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) known-answer test vectors from [FIPS 202 §D.4/D.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), cross-checked against [Python `hashlib`](https://docs.python.org/3/library/hashlib.html).

**Supported primitives**: X25519 (RFC 7748), Ed25519 (RFC 8032), ChaCha20-Poly1305 (RFC 8439), HKDF-SHA256 (RFC 5869), HMAC-SHA256 (RFC 2104), SHA-256 (RFC 6234), SHAKE256 (FIPS 202 §8.4), SHAKE128 (FIPS 202 §8.3), and ML-DSA-44 (FIPS 204) — the latter in pure-Kotlin-only mode with no native fallback. ML-DSA-44 uses the NIST PQC CAVP test vectors (Wycheproof `mldsa_44_*`) as the correctness oracle.

**Target scope**: JVM + Android (API >= 21) + iOS arm64 (Darwin native). JS and Kotlin/Native WASM targets are out of scope. Use latest stable Kotlin Multiplatform only (2.4.10). No legacy `javax.crypto`/`BouncyCastle`/old Java — modern platform providers only. _Avoid_: JS/WASM, Android APIs < 21.

**Fallback**: When a target's native provider offers a given primitive, it is used; otherwise the pure-Kotlin implementation is used as a fallback. Substitution is **per-primitive** (each RFC primitive is independently native-or-pure-K), reached per-platform via: modern `java.security` on JVM, Android KeyStore on Android, CommonCrypto / Security.framework via Kotlin/Native interop on iOS. _Avoid_: `BigInteger`-based native paths, per-step substitution.

**Core module scope**: `crypto-kmp` is primitives + fallback only. Persistent key storage is explicitly out of this module — see ADR-0004. _Avoid_: Keystore/Keychain in the core API.

## Decisions so far

- ADR-0001 — Field arithmetic: radix-2^26, 10 limbs, no `BigInteger` (shared engine for X25519 + Ed25519).
- ADR-0002 — Fallback strategy: per-primitive, native-or-pure-K.
- ADR-0003 — Verification gates: NIST CAVP + Wycheproof + constant-time lint + per-target test harness.
- ADR-0004 — Secure storage is out of core scope (separate module).
- ADR-0005 — API surface: typed, no-throw, internal nonce, transparent fallback.
- ADR-0006 — Module layout: single shared KMP module.
- ADR-0007 — Build toolchain: ktfmt + detekt (incl. const-time lint) + kover (100% coverage, pure-K path).
- Post-quantum support: FIPS 202 (SHAKE) is used by ML-DSA-44 (FIPS 204 §7). ML-DSA-44 is implemented as pure-Kotlin; ML-KEM-512 (FIPS 203) is planned. FIPS 203/204 specs stored in `docs/rfcs/crypto/`.

## Rules

- Be opinionated: when multiple words fit a concept, pin one and list others under `_Avoid_`.
- Keep definitions tight: one or two sentences, define what a term IS, not what it does.
- Pin terms here when they settle; this glossary is the project's ubiquitous language.

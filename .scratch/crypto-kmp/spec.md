# crypto-kmp: pure-Kotlin constant-time cryptography for Kotlin Multiplatform

Status: ready-for-agent

## Problem Statement

A developer shipping a Kotlin Multiplatform application (JVM, Android, iOS) needs RFC-standard
cryptography — X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, and SHA-256 — that
behaves identically and securely on every target, including older Android (API 21+) and JVM where a
primitive may not be offered natively. They need it without pulling in external dependency-heavy
providers, and without exposing secret key material to timing side-channels: on the JVM, branching
(`if`/`else`) and data-dependent array access compile to data-dependent CPU timing, and classes such as
`BigInteger` leak bit lengths. Today, the secure, portable, dependency-free option for these primitives
does not exist in KMP form.

## Solution

`crypto-kmp`: a single Kotlin Multiplatform module providing **pure-Kotlin, constant-time**
implementations of the six RFC primitives, with **per-primitive fallback** to each target's native
provider when it is available.

- Pure-K path: constant-time by construction — bitwise operations only, a 10-limb radix-2^26 GF(2^255)
  field engine with `cswap` for the curve operations (X25519 + Ed25519), 32-bit word arithmetic for the
  SHA-256 family, and constant-time comparison (never `BigInteger`, never early-exit `contentEquals`).
- Native fallback: modern `java.security` on JVM, Android KeyStore on Android, CommonCrypto /
  Security.framework (via Kotlin/Native interop) on iOS — selected per primitive, so a target can mix
  native and pure-K within one algorithm family.
- API: small, hard-to-misuse, no-throw (`Result`-returning), stateless and thread-safe. Keys are typed
  handles (`PrivateKey`/`PublicKey`/`SecretKey`) backed by `ByteArray`s that are wiped on close. The
  AEAD nonce is generated internally (caller never supplies one).
- Key storage is out of this module: no persistent key API (consumers use Android KeyStore / iOS
  Keychain as they see fit).
- Verification: Wycheproof vectors for every primitive, a constant-time static lint, and per-target
  timing-variance tests on the pure-K path.

Kotlin 2.4.10 (latest stable) is the build target; no legacy `javax.crypto`/`BouncyCastle` provider
plumbing in the pure-K path.

## User Stories

1. As a JVM (server-side) developer, I want X25519 key agreement with a pure-K fallback, so my service
   runs without a native crypto dependency when the runtime lacks it.
2. As an Android developer targeting API 21+, I want Ed25519 signing backed by Android KeyStore when
   present, so I get hardware-backed keys on capable devices and pure-K on older ones, without leaking
   key bits through timing.
3. As an iOS developer, I want ChaCha20-Poly1305 authenticated encryption with a pure-K path, so my
   app is secure on iOS arm64 without a third-party crypto pod.
4. As a library consumer, I want all six primitives to return identical results for identical inputs
   regardless of target, so my protocol interop holds across platforms.
5. As a security reviewer, I want the pure-K path to be constant-time — verified by Wycheproof vectors,
   a constant-time lint, and per-target timing tests — so I can trust it with long-lived secret keys
   without relying on manual review alone.
6. As a mobile app developer, I want the AEAD nonce handled internally, so I cannot accidentally reuse a
   nonce and break ChaCha20-Poly1305.
7. As a caller, I want key handles that wipe themselves when closed, so secret material does not linger
   in heap memory after I am done with it.
8. As a caller, I want operations that return `Result` and never throw, so every error path is explicit
   and I cannot silently ignore a failed crypto operation.
9. As a user of the library, I want each primitive to be stateless and thread-safe, so I can call it
   concurrently from multiple coroutines/threads without synchronization.
10. As a Kotlin developer, I want the library to have zero external runtime dependencies, so it does not
    pull transitive crypto or ASN.1 dependencies into my dependency graph.
11. As an app developer, I want secure key storage to stay in my own Android KeyStore / iOS Keychain
    layer, so this library stays a focused primitives module and does not own my key lifecycle.
12. As a maintainer, I want per-primitive fallback selection tests per target, so I can prove the native
    path is used when available and the pure-K path is reached otherwise (and is always tested).
13. As a JVM developer on an older runtime, I want HKDF-SHA256 and HMAC-SHA256 in pure Kotlin, so key
    derivation in a zero-trust pipeline does not depend on a JCE provider.
14. As a protocol implementer, I want SHA-256 to match the RFC 6234 test vectors exactly, so my hashes are
    interoperable with other implementations.
15. As an SRE, I want the constant-time lint to fail the build if a secret-data scope gains
    data-dependent branching or indexing, so side-channel regressions are caught in CI.

## Implementation Decisions

- **Module layout**: a single shared KMP module (`commonMain` + `jvmMain`/`androidMain`/`iosMain`)
  (ADR-0006). The 10-limb field engine lives once in `commonMain`, shared by X25519 and Ed25519; each
  primitive's native `actual` is independent.
- **Field arithmetic**: 10-limb radix-2^26 GF(2^255) field engine, `cswap`, no `BigInteger`, shared by
  the curve primitives (ADR-0001); SHA-256/HMAC/HKDF/ChaCha20 use separate 32-bit word arithmetic.
- **Fallback**: per-primitive, native-or-pure-K, reached per platform (ADR-0002).
- **Verification gates**: Wycheproof + constant-time lint + per-target timing harness on the pure-K path
  (ADR-0003).
- **Storage**: out of core scope; no persistent key API (ADR-0004).
- **API surface**: typed wiping `Closeable` key handles, internal AEAD nonce, transparent fallback,
  no-throw `Result`, stateless/thread-safe (ADR-0005).
- **Versions & targets**: Kotlin 2.4.10 (latest stable); JVM + Android API 21+ + iOS arm64; JS/WASM
  out of scope; no legacy `javax.crypto`/`BouncyCastle` provider plumbing in the pure-K path.
- **Domain language**: governed by the project glossary and ADRs recorded during grilling.

## Testing Decisions

What makes a good test here: external behavior only — Wycheproof vectors (correctness), determinism and
cross-target equivalence (interoperability), and timing-variance (constant-time). Never assertions on
internal state of the field engine.

**Proposed testing seams** (please confirm before tickets are cut):

1. **Common-API seam (highest, preferred)** — the `expect` API surface exercised in `commonMain` by
   Wycheproof vectors + the constant-time lint + a timing-variance harness. One seam, reused by every
   primitive. This is the seam that proves correctness and constant-time-ness of the pure-K path.
2. **Per-target native-fallback seam** — for each primitive on each target, assert the native provider is
   used when the platform offers it and pure-K is reached otherwise. Necessary because fallback is
   per-primitive per-target; adds no new common-code seam, and reuses seam 1 for the pure-K side.
3. **Constant-time guarantee** — static lint (bans data-dependent branching/indexing in secret scopes) +
   per-target instrumentation (Android Systrace / iOS Instruments). This is how a constant-time library
   is validated, not a separate code seam (ADR-0003).

Prior art: Wycheproof (vectors); BoringSSL `crypto/curve25519` + ref10 (constant-time structure); Tink
API design (hard-to-misuse); signum (native-interop + key-storage + no-throw API shape in KMP).

## Out of Scope

- Persistent / secured key storage and cross-process key lifecycle (Android KeyStore / iOS Keychain are
  the consumer's layer) (ADR-0004).
- JS and Kotlin/Native WASM targets.
- Android APIs below 21.
- Legacy `javax.crypto`/`BouncyCastle` as the pure-K path; modern `java.security` is permitted only as
  the native-fallback provider on the JVM.
- RSA, AES-GCM, and other primitives beyond the six RFC primitives above.

## Further Notes

- Primitive spec texts: RFC 7748, 8032, 8439, 5869, 2104, 6234 (texts in `docs/rfcs/`; RFC 7539 present
  is obsolete — RFC 8439 is active).
- Implementation guidance collected in `research/`: KMP security architecture, Secure Storage (Android +
  iOS), the Tink reference, and the signum + BoringSSL reference audit.
- The pure-K constant-time field engine is corroborated by BoringSSL's `crypto/curve25519` and
  ref10/X25519-daleed; signum is referenced for the native-interop / storage / API shape only, not for
  the pure-K arithmetic.

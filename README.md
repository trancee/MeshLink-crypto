# MeshLink-crypto

[![AI Ready](https://img.shields.io/badge/AI--Ready-yes-brightgreen?style=flat)](https://github.com/johnpapa/ai-ready)

MeshLink-crypto provides pure-Kotlin, constant-time cryptographic primitives for Kotlin Multiplatform, with per-primitive native fallback.

## What it is

MeshLink-crypto provides eleven RFC/FIPS-standard cryptographic primitives as pure-Kotlin, constant-time implementations. Each primitive also has a native fallback path. The library selects per-primitive at each call site. Callers never choose a provider. ML-DSA-44 (FIPS 204) is implemented as pure-Kotlin only — native integration is pending.

The library targets **JVM**, **Android (API 21+)**, and **iOS (arm64 + simulator)**. JS and WebAssembly targets are out of scope. Built with Kotlin 2.4.10.

## What is provided

| Primitive | RFC | Pure-K | Native fallback |
|---|---|---|---|
| SHA-256 | [RFC 6234 §5.1](https://datatracker.ietf.org/doc/html/rfc6234#section-5.1) | Yes | JCA, CommonCrypto |
| SHA-512 | [RFC 6234 §5.2](https://datatracker.ietf.org/doc/html/rfc6234#section-5.2) | Yes | JCA, CommonCrypto |
| SHA3-256 | [FIPS 202 §6.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | Yes | JCA (JDK 9+, API 28+); Pure-K (iOS) |
| SHA3-512 | [FIPS 202 §6.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | Yes | JCA (JDK 9+, API 28+); Pure-K (iOS) |
| HMAC-SHA256 | [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | Yes | JCA Mac, CCHmac |
| HKDF-SHA256 | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | Yes | Platform HMAC |
| X25519 | [RFC 7748 §5](https://datatracker.ietf.org/doc/html/rfc7748#section-5) | Yes | JCA KeyAgreement, Security.framework |
| Ed25519 | [RFC 8032 §5.1](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1) | Yes | JCA Signature, Security.framework |
| ChaCha20-Poly1305 | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) | Yes | JCA Cipher, CryptoKit (iOS) |
| SHAKE256 | [FIPS 202 §8.4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | Yes | Pure-K only (no native) |
| SHAKE128 | [FIPS 202 §8.3](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | Yes | Pure-K only (no native) |
| ML-DSA-44 | [FIPS 204 §7](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) | Yes | Pure-K only (in development) |

## How it works

The library has three layers of dispatch, per primitive:

1. **Optional CryptoProvider** — a consuming app can inject a platform-native provider at runtime (CryptoKit on iOS, custom JCA on JVM/Android).
2. **Native C-API / JCA** — the library calls the host platform's native crypto directly (CommonCrypto, Security.framework, `java.security`, `javax.crypto`).
3. **Pure-Kotlin fallback** — if the native path is unavailable, the library falls back to its own constant-time implementation compiled from the same shared source.

The pure-Kotlin path is the only code that holds secrets and is authored in-house. It is held to three verification gates:

- **NIST CAVP test vectors** as the correctness oracle ([Wycheproof](https://github.com/google/wycheproof) for primitives with a corpus; [FIPS 202 §D.4/D.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) KAT vectors for SHAKE128/SHAKE256, verified against [Python `hashlib`](https://docs.python.org/3/library/hashlib.html) and cross-checked with the [XKCP](https://github.com/XKCP/XKCP) reference implementation).
- **Custom constant-time lint** (`ConstantTimeRule`) that bans data-dependent branches and secret-indexed array access at compile time.
- **Timing harness** that asserts no early-exit in secret comparisons.

See [Architecture](docs/explanation/architecture.md) for the full design and [Constant-Time Discipline](docs/explanation/constant-time.md) for the security model.

## External references

| Reference | URL | Purpose in this repo |
|---|---|---|
| [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) | NIST FIPS 202 standard | Defines SHA-3, SHAKE128 (§8.3), SHAKE256 (§8.4) — the spec for our Keccak/XOF primitives |
| [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) | Cryptographic Algorithm Validation Program | Known Answer Test vectors for SHAKE128/SHAKE256 — correctness oracle for primitives without a Wycheproof corpus |
| [XKCP / Keccak Team](https://github.com/XKCP/XKCP) | eXtending Keccak Code Package | Reference implementation for Keccak-f[1600] round constants, rotation constants, and `SimpleFIPS202.c` — our implementation is verified byte-identical to XKCP parameters |
| [Wycheproof](https://github.com/google/wycheproof) | Google's crypto test-vector corpus | Correctness oracle for primitives with a corpus: AES-GCM, Ed25519, HKDF-SHA256, HMAC-SHA256, X25519, ChaCha20-Poly1305, ML-DSA-44, ML-KEM-512 |
| [Python `hashlib`](https://docs.python.org/3/library/hashlib.html) | Python standard library | Cross-check reference: SHAKE128/SHAKE256 outputs verified against `hashlib.shake_128`/`shake_256` (FIPS 202-compliant, byte-identical to CAVP) |
| [RFC 6234](https://datatracker.ietf.org/doc/html/rfc6234) | SHA-2 Hashed Data | Defines SHA-256 (§5.1) and SHA-512 (§5.2) — our SHA-2 implementations |
| [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | HMAC | Defines HMAC-SHA256 — our HMAC implementation |
| [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | HKDF | Defines HKDF-SHA256 (Extract + Expand) — our KDF implementation |
| [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) | Curve25519 / X25519 | Defines X25519 key agreement — our key exchange primitive |
| [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) | EdDSA | Defines Ed25519 signing — our signature primitive |
| [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) | ChaCha20/Poly1305 | Defines ChaCha20-Poly1305 AEAD — our encryption primitive |
| [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) | ML-DSA (CRYSTALS-Dilithium) | Defines ML-DSA-44 post-quantum signature scheme — our post-quantum signature primitive |
| [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) | ML-KEM (CRYSTALS-Kyber) | Defines ML-KEM-512/768/1024 key-encapsulation mechanisms — referenced for future PQC KEM support; spec stored in `docs/rfcs/crypto/fips203.pdf` |
| [RFC 9688](https://datatracker.ietf.org/doc/html/rfc9688) | SHA3 in CMS | Use of SHA3 one-way hash functions in CMS — reference for SHA3 integration (not yet implemented) |
| [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) | HPKE | Hybrid Public Key Encryption — reference for PQC KEM integration (HPKE-ML-KEM, not yet implemented) |
| [RFC 9629](https://datatracker.ietf.org/doc/html/rfc9629) | KEM in CMS | Using Key Encapsulation Mechanism (KEM) Algorithms in CMS — reference for future PQC KEM support |
| [RFC 9861](https://datatracker.ietf.org/doc/html/rfc9861) | KangarooTwelve / TurboSHAKE | Defines KangarooTwelve and TurboSHAKE XOFs based on Keccak — reference for Keccak family extensions |
| [RFC 9794](https://datatracker.ietf.org/doc/html/rfc9794) | PQ hybrid terminology | Terminology for post-quantum traditional hybrid schemes — reference for PQ transition design |
| [RFC 9958](https://datatracker.ietf.org/doc/html/rfc9958) | PQC for engineers | Practical guidance on post-quantum cryptography deployment — engineering reference |

## Quick start

```kotlin
import ch.trancee.meshlink.crypto.Crypto
import ch.trancee.meshlink.crypto.SecretKey

// Sample data (replace with your own key material)
val ikm = ByteArray(32) { 0x01 }     // input keying material
val salt = ByteArray(16) { 0x00 }    // public salt (empty is also valid)
val info = byteArrayOf(0x01, 0x02)   // public context string
val plaintext = "Hello, world!".encodeToByteArray()

// Hash — RFC 6234
val digest = Crypto.sha256(plaintext).getOrThrow()

// Derive a session key with HKDF — RFC 5869
val sessionKey = Crypto.hkdfSha256(ikm, salt, info, outputLength = 32).getOrThrow()

// Encrypt — ChaCha20-Poly1305 (RFC 8439). Nonce is generated internally.
SecretKey(sessionKey).use { key ->
    val encrypted = Crypto.chacha20Poly1305Encrypt(key, plaintext).getOrThrow()
    // encrypted = nonce(12) || ciphertext || tag(16)
    val decrypted = Crypto.chacha20Poly1305Decrypt(key, encrypted).getOrThrow()
}
```

See [How to Get Started](docs/how-to/get-started.md) for adding the dependency to your project.

## Documentation

### Getting started

- [How to: Get Started](docs/how-to/get-started.md) — add the dependency and make your first call
- [Tutorial: First Encryption](docs/tutorials/first-encryption.md) — encrypt and decrypt a message step by step

### How-to guides

- [How to: Integrate into a KMP Project](docs/how-to/integrate-kmp.md)
- [How to: Run Tests and Quality Gates](docs/how-to/run-checks.md)
- [How to: Prepare a Release](docs/how-to/prepare-release.md)
- [How to: Add a Crypto Primitive](docs/how-to/add-primitive.md)
- [How to: Follow Security and Usage Best Practices](docs/how-to/best-practices.md)

### Reference

- [API Reference](docs/reference/api-reference.md) — full public API surface
- [Supported Primitives](docs/reference/supported-primitives.md) — primitives table with RFC and platform mapping

### Explanation

- [Architecture](docs/explanation/architecture.md) — dispatch, module layout, pure-K engines
- [Constant-Time Discipline](docs/explanation/constant-time.md) — `@Secret`, the detekt rule, and the timing harness

### Architecture decisions (ADRs)

- [ADR-0001](docs/adr/0001-field-arithmetic-radix-2-26.md) — Field arithmetic: radix-2^26, 10 limbs
- [ADR-0002](docs/adr/0002-fallback-strategy.md) — Per-primitive native-or-pure-K fallback
- [ADR-0003](docs/adr/0003-verification-gates.md) — Wycheproof + constant-time lint + timing harness
- [ADR-0004](docs/adr/0004-secure-storage-out-of-core-scope.md) — Secure storage is out of scope
- [ADR-0005](docs/adr/0005-api-surface.md) — Typed keys, internal nonce, no-throw API
- [ADR-0006](docs/adr/0006-module-layout.md) — Single shared KMP module
- [ADR-0007](docs/adr/0007-build-quality-toolchain.md) — ktfmt + detekt + kover + abiValidation
- [ADR-0008](docs/adr/0008-skie-excluded.md) — SKIE excluded

### Contributing resources

- [CONTRIBUTING.md](CONTRIBUTING.md) — prerequisites, build, test, and git hooks
- [Contributing a crypto primitive](docs/how-to/add-primitive.md) — step-by-step
- [Build & test conventions](docs/agents/build.md) — Gradle flags, kover, detekt
- [Agent workflow](docs/agents/workflow.md) — the 5-step agent workflow

### Other

- [CONTEXT.md](CONTEXT.md) — domain glossary and terminology
- [SECURITY.md](SECURITY.md) — vulnerability reporting policy
- [docs/proposals/](docs/proposals/) — design proposals
- [docs/rfcs/](docs/rfcs/) — RFC spec texts and FIPS publications used as references (FIPS 202/203/204, RFC 2104/5869/6234/7748/8032/8439/9180/9629/9688/9794/9861/9958)

## Contributing

1. Open a GitHub issue first.
2. Implement the primitive with test vectors ([NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) / [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) KAT vectors for FIPS primitives like SHAKE128/SHAKE256; [Wycheproof](https://github.com/google/wycheproof) vectors where a corpus exists), green constant-time lint, and 100% coverage on the pure-K path.
3. Run `./gradlew check --rerun-tasks --no-build-cache` locally.
4. Open a pull request with a Conventional Commit message.

Code of conduct: be respectful. Security issues are reported via [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE).

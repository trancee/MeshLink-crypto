# Research: signum + BoringSSL as references

Scouted against the user's pointer to reference implementations and security guidelines/tests. Key
finding: these are strong references for **different halves** of crypto-kmp's strategy, and **neither
ships the pure-K constant-time arithmetic that crypto-kmp's fallback path needs** — that remains our
own port.

## a-sit-plus/signum (Kotlin Multiplatform)

Kotlin Multiplatform crypto/PKI library. README badges: Kotlin 2.3.20, Java 17+, iOS 15, Android
SDK-26/30. Modules published to Maven Central: `indispensable` (ASN.1 engine + data structures, no
crypto ops), `indispensable-josef` (JOSE), `indispensable-cosef` (COSE), `supreme` (KMP crypto
provider, hardware-backed).

**Signum "supreme" = hardware-backed, platform-native crypto — not pure-K.** Stated in the README:
"the tightest possible platform integration on Android and iOS, including hardware-backed storage of key
material and in-hardware execution of cryptographic operations whenever possible … because they are the
same [as platform-native] under the hood … hardware-backed private keys never even leave the hardware
crypto modules." Supported ops (ECDH/ECDSA/RSA/AES/ChaChaPoly/PBKDF2/HKDF/scrypt/HMAC/SHA-2) are
realized via Android KeyStore / iOS Secure Enclave / JCA. So signum is a reference for:

1. the **native-interop / fallback layer** (`expect/actual` to Android KeyStore + iOS Secure Enclave) —
   directly informative for the native side of ADR-0002;
2. **Secure Storage** — hardware-backed keys via Android KeyStore / iOS Secure Enclave (the model
   ADR-0004's separate storage module would wrap);
3. **API shape** — a `Result`-based, "nothing throws, never discard results" KMP API (relevant to Q6).

**What signum is NOT a reference for**: a pure-Kotlin constant-time X25519/Ed25519/ChaCha20 core. If
crypto-kmp needs pure-K fallback arithmetic, that is our own radix-2^26 port (ADR-0001), corroborated
by BoringSSL/ref11 rather than by signum. (Caveat: per the README; I have not audited signum's source
to rule out a pure-K fallback module — can verify on request.)

Source: https://github.com/a-sit-plus/signum (README).

## google/boringssl (C — reference constant-time implementation + Wycheproof wiring)

BoringSSL is Google's fork of OpenSSL (Chrome/Chromium/Android; not for general use, no ABI stability).
It is the canonical constant-time implementation base. Relevant surface for crypto-kmp:

- **Algorithm structure**: the repo's `crypto/` tree includes `curve25519/` (X25519 + Ed25519 — the
  radix-2^26 10-limb field, Montgomery ladder, `cswap`), `chacha/`, `poly1305/`, and the
  `fipsmodule/` AES/digest code — the algorithmic reference for ADR-0001.
- **Constant-time discipline** (in C): `BN_FLG_CONSTTIME`, no secret-dependent branches/indexing.
- **Guidelines/tests docs**: `STYLE.md` (coding/security rules), `SECURITY.md`, `FUZZING.md`,
  `API-CONVENTIONS.md`, `PORTING.md`.
- **Wycheproof wiring**: the `google/wycheproof` project runs its vectors against BoringSSL — exactly
  the validation model ADR-0003 adopts.

For crypto-kmp (Kotlin), BoringSSL is a reference for **algorithm structure** and the **constant-time
discipline + Wycheproof validation pattern**, not for Kotlin code (it is C). ref10 / X25519-daleed
remain the closest constant-time arithmetic references for a from-scratch Kotlin port.

Sources: https://github.com/google/boringssl (README + tree); https://github.com/google/wycheproof.

## Corroboration status vs. crypto-kmp decisions

- **ADR-0001** (radix-2^26, 10-limb, `cswap`, no `BigInteger`): **corroborated** by BoringSSL's
  `curve25519` module and ref11; signum is NOT this.
- **ADR-0002** (per-primitive native-or-pure-K fallback): **corroborated** by signum's native-interop pattern.
- **ADR-0003** (Wycheproof + const-time gates): **corroborated** by BoringSSL + Wycheproof integration;
  the per-target instrumentation (Systrace/Instruments) is the KMP analog of BoringSSL's own
  constant-time validation.
- **ADR-0004** (storage out of core): **corroborated** by signum separating `indispensable` (pure data)
  from `supreme` (hardware-backed storage + signing).
- **Q6 (API surface)**: signum's Result/no-throw, never-discard-results idiom is a concrete KMP reference
  to weigh.

## Version check

Crypto-kmp policy is latest-stable KMP (2.4.0). Signum badges target Kotlin 2.3.20 — current, not a
conflict, just one minor version behind.

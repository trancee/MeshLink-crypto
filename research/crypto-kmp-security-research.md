# Research: crypto-kmp security architecture & Secure Storage

Findings gathered while grilling the `crypto-kmp` idea. Primary sources linked inline.

## 1. KMP crypto architecture (best practice)

Put a thin, platform-agnostic API in `commonMain` via `expect` declarations; provide `actual`
implementations that delegate to native, hardware-backed libraries:

- iOS — CryptoKit / Secure Enclave
- Android — Android Keystore / Conscrypt
- other native targets — libsodium or OpenSSL (KMP-built)

Heavy crypto runs in constant-time primitives supplied by the OS. Secrets stay in immutable
`ByteArray`, wiped after use; avoid Kotlin collection abstractions that allocate/copy unpredictably.
Use platform constant-time comparison helpers (or a well-audited pure-Kotlin impl) for MAC/signature
verification; never expose intermediates via logs/exceptions. Wrap native APIs in small
`expect/actual` classes marked `internal`/`private`. Tests run on each target, including
side-channel (timing-variance) checks; confirm constant-time via platform instrumentation
(Android Systrace, iOS Instruments).

Sources: Medium — "Building Hardware-Backed Security with Kotlin Multiplatform";
LinkedIn — "Kotlin Multiplatform Crypto: CommonCrypto vs JCE";
Android Developers — Kotlin Multiplatform docs.

Implication: this validates ADR-0001 (radix-2^26, no `BigInteger`, constant-time) and ADR-0003
(verification gates). The per-primitive fallback (ADR-0002) is exactly the `expect/actual` idiom —
native when the target offers a primitive, pure-K otherwise.

## 2. Secure Storage on Android (modern, no older Java concepts)

- AndroidX Security `MasterKey` wraps the Android Keystore → AES-256-GCM (or AES-256-SIV) key for
  `EncryptedSharedPreferences`.
- As of `androidx.security:security-crypto` 1.1.0, **EncryptedSharedPreferences is deprecated** in
  favor of direct Android Keystore (optionally via Tink) + Jetpack DataStore for structured prefs.
- New KMP code should use Android Keystore + DataStore/Tink, not EncryptedSharedPreferences.

Sources: Medium — "From EncryptedSharedPreferences to DataStore, Tink and Keystore in a KMP credential
store"; Android Developers — "Android Keystore system".

## 3. Secure Storage on iOS (Kotlin/Native)

- iOS Keychain via the Security framework through Kotlin/Native c-interop:
  - bindings for `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`;
  - `.def` file `#import <Security/Security.h>`, run `cinterop` to produce a `Security` interop package;
  - thin, type-safe `actual` wrapper over a common `expect` `SecureStorage` (save/read/delete),
    Kotlin types ↔ CFDictionary queries, OS status codes handled, `kotlinx.cinterop` for memory.
- Same `expect/actual` `SecureStorage` interface backed by Android Keystore on Android → one
  cross-platform secure-storage API.

Sources: Apple — Security framework (Keychain) docs; Kotlin — Kotlin/Native c-interop docs.

## 4. Latest Kotlin / KMP version

- Latest stable Kotlin: **2.4.10** (bug-fix release for the 2.4 language line; released July 2026).
- Kotlin Multiplatform stable since 1.9.20 (Nov 2023); fully supported in the 2.4 line.
- Version policy (pinned in `CONTEXT.md` "Target scope"): latest stable KMP only.

Sources: kotlinlang.org — Kotlin release process (releases.html) confirms 2.4.10 as the latest stable
bug-fix release.

## 5. Tink (reference) — API architecture & security design, not pure-K arithmetic

Tink is Google's secure-by-default crypto library (github.com/google/tink, now split to
github.com/tink-crypto; docs at developers.google.com/tink). Design goals (`docs/SECURITY-USABILITY.md`)
relevant to crypto-kmp:

- **Security** built on BoringSSL/JCA but adding countermeasures to weaknesses found by **Project
  Wycheproof** — directly reinforces ADR-0003's Wycheproof oracle.
- **Hard-to-misuse** interfaces that encode security guarantees and disallow misuse (e.g. the nonce is
  not exposed to the caller → nonce-misuse resistant). Relevant to ADR-0005 (API surface): typed,
  no-throw handles + internal AEAD nonce.
- **Stateless & thread-safe** primitives (`docs/PRIMITIVES.md`) — matches ADR-0005's guarantee.
- **Crypto agility / modularity**: swap implementations without recompiling; "exclude what you don't
  need" — echoes ADR-0002 (per-primitive native-or-pure-K) and ADR-0006 (single cohesive module).
- Supports Android Keystore / iOS Keychain as key-management back ends — reinforces that key *storage*
  is a separate seam from key *crypto* (ADR-0004).

⚠️ **Not a pure-K reference**: Tink delegates to BoringSSL/JCA, so it does **not** implement the
radix-2^26 constant-time arithmetic crypto-kmp owns. The reference for that is BoringSSL's
`crypto/curve25519` + ref10/X25519-daleed + Wycheproof validation. Tink is the reference for *API shape*
and *security architecture*, not for Kotlin arithmetic. Tink also advises "always use the latest stable
release" — corroborates the version policy.

Sources: github.com/google/tink `docs/SECURITY-USABILITY.md`, `docs/PRIMITIVES.md` (primary).

## 6. signum + BoringSSL reference audit (scout)

- **signum** (`a-sit-plus/signum`, KMP): a KMP crypto/PKI library whose `supreme` provider realizes
  X25519/Ed25519/ChaCha20-Poly1305/HKDF/HMAC/SHA-256 via **platform-native** crypto (Android KeyStore,
  iOS Secure Enclave, JCA) — hardware-backed, "never leaves the hardware." It does **not** ship a
  pure-Kotlin constant-time arithmetic core (the only hand-rolled crypto is a standalone SHA-256 utility
  in `indispensable-josef`, public domain). Reference for crypto-kmp's **native-interop layer,
  hardware-backed key storage, and API shape (Result/no-throw)** — not for the pure-K field engine.
- **BoringSSL** (C, Google fork of OpenSSL): the canonical **constant-time** reference. `crypto/curve25519`
  holds the X25519/Ed25519 field arithmetic (radix-2^26, cswap-style), `crypto/chacha`,
  `crypto/poly1305`, `crypto/digest` (SHA-256), `crypto/hkdf`, `crypto/hmac`. Constant-time idioms via
  `BN_FLG_CONSTTIME` and the no-secret-branch/indexing discipline. Security/guidance docs: `STYLE.md`,
  `SECURITY.md`, `FUZZING.md`, `API-CONVENTIONS.md`. Its vectors are what **Project Wycheproof** runs
  against — the validation model ADR-0003 adopts.
- Net: the **pure-K radix-2^26 engine (ADR-0001)** is corroborated by BoringSSL's `curve25519` + ref10;
  signum corroborates the native-storage/API half (ADR-0002/0004/0005). Neither is borrowed as Kotlin code.

Sources: github.com/a-sit-plus/signum (README); github.com/google/boringssl (README + tree).

## Spec sources

Algorithm spec texts live in `docs/rfcs/` (RFC 7748, 8032, 8439, 5869, 2104, 6234), per the RFC files
added under `docs/rfcs/crypto/`. Note: RFC 7539 (also present in `docs/rfcs/crypto/`) is obsolete;
RFC 8439 is the active ChaCha20/Poly1305 spec.

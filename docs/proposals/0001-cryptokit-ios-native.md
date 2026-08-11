# Proposal: iOS Native Crypto — CryptoKit via Dependency Inversion

## Status

accepted

## Context

We analyzed three inputs for wiring iOS native crypto into the
`crypto-kmp` `iosMain` source set:

1. Medium article by Mubashirmurtaza — proposes `expect/actual` + runtime callback
   injection from Swift.
2. Old `MeshLink.old/meshlink/src/appleMain/` — `CryptoProvider.kt` has a TODO for
   CryptoKit via cinterop with a `.def` file.
3. Kotlin docs — Apple SDK deps (CoreCrypto, Security) are prebuilt bindings;
   "Pure Swift dependencies are not yet supported."

### Critical constraint: CryptoKit is Swift-only

CryptoKit relies on modern Swift features (generics, opaque return types).
Kotlin/Native cinterop parses only Objective-C headers. Therefore:

- **CryptoKit cannot be cinterop'd directly from KMP.** The old TODO's claim
  that "adding a .def file for CryptoKit" will work is **incorrect**.
- The Apple SDK provides C frameworks (CommonCrypto, Security.framework) as
  as prebuilt `platform.*` bindings with no `.def` file — already used by the
  project for SHA-256, SHA-512, HMAC, and CSPRNG.

### Two valid approaches

| Approach | Scope | How it works |
|---|---|---|
| **C-API interop** (CommonCrypto + Security.framework) | Library-internal | `iosMain` actuals call `platform.CoreCrypto` / `platform.Security` C functions directly. Same hardware acceleration as CryptoKit (CryptoKit wraps these C APIs). Pure-K fallback for older OS. |
| **Dependency inversion** (Swift CryptoKit) | App-integration | `commonMain` declares interfaces; consuming iOS app implements them in Swift using CryptoKit; implementations injected at runtime. |

## Decision

**Use C-API interop as the library's primary native path.** This matches the
existing pattern (SHA256, SHA512, HMAC_SHA256, Random already use it), requires
no build config changes, needs no `.def` file, and provides the same
hardware-accelerated crypto that CryptoKit wraps internally.

**Expose an optional dependency-inversion seam** so consuming apps can swap in
a CryptoKit + Secure Enclave backed implementation if they need features the
C APIs cannot provide (e.g., keys that never leave the Secure Enclave).

This rejects the Medium article's callback injection for two reasons:
- It has no pure-K fallback (callers get `""` if no callback is set).
- The project's design already has a superior pattern (per-primitive
  native-or-pure-K via expect/actual + cinterop).

## Part 1: C-API interop (library-internal native path) — IMPLEMENTED

### Already done on iOS

| Primitive | API | Min iOS |
|---|---|---|
| SHA-256 | `CC_SHA256` | any |
| SHA-512 | `CC_SHA512` | any |
| HMAC-SHA256 | `CCHmac` | any |
| CSPRNG | `SecRandomCopyBytes` | any |

### To implement in `iosMain` actuals

|| Primitive | C API | Min iOS | Pure-K fallback |
||---|---|---|---|
|| X25519 | `SecKeyCopyKeyExchangeResult` with `kSecAttrKeyTypeX25519` + `kSecKeyAlgorithmECDHKeyExchangeStandardX` (Swift-only CFString) | 14.0 | `X25519PureK` |
|| Ed25519 | `SecKeyCreateSignature` / `SecKeyVerifySignature` with `kSecAttrKeyTypeEd25519` + `kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512` (Swift-only CFString) | 14.0 | `Ed25519PureK` |
|| ChaCha20-Poly1305 | No C API in CommonCrypto — CryptoKit provider only (Layer 2) | — (iOS < 15 falls back to PureK) | `ChaCha20Poly1305PureK` |
|| HKDF | No C API exists | — | `HKDF_SHA256PureK` (same as JVM/Android) |

### X25519 via Security.framework

`SecKeyCopyKeyExchangeResult` performs X25519 key agreement (iOS 14+).

**Swift-only constants**: `kSecAttrKeyTypeX25519` and `kSecKeyAlgorithmECDHKeyExchangeStandardX`
Security.tbd exports them as binary symbols, but the C headers do not include
them. We recreate them as `CFStringRef` via
`CFStringCreateWithCString` with the correct string values.

```
iosMain actual X25519.compute(scalar, u):
  1. SecKeyCreateWithData(scalar, attributes={kSecAttrKeyType: kSecAttrKeyTypeX25519,
     kSecAttrKeyClass: kSecAttrKeyClassPrivate})
  2. SecKeyCreateWithData(u, attributes={kSecAttrKeyType: kSecAttrKeyTypeX25519,
     kSecAttrKeyClass: kSecAttrKeyClassPublic})
  3. SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, params, error)
     // algorithm = kSecKeyAlgorithmECDHKeyExchangeStandardX (Swift-only CFString)
  4. Extract 32 bytes from returned CFData
  5. On any NULL/unhandled error -> return X25519PureK.compute(scalar, u)
```

**Byte order note**: iOS `SecKeyCreateWithData` for Curve25519 accepts raw
little-endian bytes (RFC 7748 wire format). No byte reversal is needed — the
project's raw key bytes are passed directly.
### Ed25519 via Security.framework

**Swift-only constants**: `kSecAttrKeyTypeEd25519` and
`kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512`. Security.tbd exports them as binary symbols, but the C headers lack
them. We recreate them as
`CFStringRef` via `CFStringCreateWithCString`.

```
iosMain actual Ed25519.publicKeyFromPrivate(secretKey):
  1. SecKeyCreateWithData(seed, attr={kSecAttrKeyType: kSecAttrKeyTypeEd25519,
     kSecAttrKeyClass: kSecAttrKeyClassPrivate})
  2. SecKeyCopyPublicKey(keyRef) -> SecKeyRef
  3. SecKeyCopyExternalRepresentation(publicKeyRef, NULL) -> CFData (32 bytes)
  4. On error -> return Ed25519PureK.publicKeyFromPrivate(secretKey)

iosMain actual Ed25519.sign(secretKey, message):
  1. SecKeyCreateWithData (as above)
  2. SecKeyCreateSignature(keyRef, kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512, message)
  3. Returns 64-byte signature (matches RFC 8032)

iosMain actual Ed25519.verify(publicKey, message, signature):
  1. SecKeyCreateWithData(publicKey, attr={kSecAttrKeyClass: kSecAttrKeyClassPublic})
  2. SecKeyVerifySignature(keyRef, algorithm, message, signature, &error)
     // algorithm = kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512 (Swift-only)
  3. On error -> return false (matching JVM/Android error semantics)
```

### ChaCha20-Poly1305 — CryptoKit provider only (no C-API path)

**Important**: `kCCModeChaCha20Poly1305` does **not** exist in CommonCrypto (not
in the iPhoneOS.sdk headers). Searching the SDK confirms CommonCrypto has no
ChaCha20-Poly1305 AEAD mode. Therefore there is no Layer 1 C-API path for
ChaCha20-Poly1305.

The native path for ChaCha20-Poly1305 goes exclusively through Layer 2 (the
injected `CryptoProvider` in Swift/CryptoKit). If no provider is injected,
the actual falls back to `ChaCha20Poly1305PureK` directly.

### HKDF — native via CCHmac

No HKDF C function exists in CommonCrypto or Security.framework, but `CCHmac`
(HMAC-SHA256) is available. The iOS `actual` delegates to
`hkdfSha256Native()` in `CryptoBridge.kt`, which implements RFC 5869
extract+expand using `hmacSha256Native` (backed by `CCHmac`). Falls back to
`HKDF_SHA256PureK` on null. This matches the JVM and Android implementation.

### Build configuration

No changes to `build.gradle.kts`. The `platform.Security` and
`platform.CoreCrypto` bindings are prebuilt. No `cInterop` block, no `.def`
file.

## Part 2: Dependency-inversion seam (app-integration path)

For consuming apps that need CryptoKit-specific features (Secure Enclave key
storage, keys that never leave hardware), expose an optional interface in
`commonMain` that the iOS app implements in Swift.

### Step 1: Declare the interface in commonMain

```kotlin
// crypto/src/commonMain/kotlin/ch/trancee/meshlink/crypto/CryptoProvider.kt

/**
 * Optional platform-native crypto provider. Apps can back it with CryptoKit + Secure Enclave.
 *
 * Consuming iOS apps can supply a Swift implementation that uses CryptoKit for
 * hardware-backed crypto where the C-API path is unavailable or insufficient
 * (e.g., Secure Enclave key storage). Each `supports*` method returns `false`
 * when the provider cannot handle a primitive — the library then falls back to
 * the per-primitive C-API or pure-K path.
 *
 * This is an escape hatch — the default iosMain actuals use CommonCrypto and
 * Security.framework C APIs directly (see Part 1). Do not set a provider unless
 * you need Secure Enclave integration.
 */
public interface CryptoProvider {

  /** Whether the provider can handle X25519 key agreement. */
  public fun supportsX25519(): Boolean

  /** X25519 key agreement. Returns null if [supportsX25519] is false. */
  public fun x25519(
      scalar: ByteArray,
      u: ByteArray,
  ): ByteArray?

  /** Whether the provider can handle Ed25519 signing/verification. */
  public fun supportsEd25519(): Boolean

  public fun ed25519PublicKeyFromPrivate(privateKey: ByteArray): ByteArray?
  public fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray?
  public fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean?

  /** Whether the provider can handle ChaCha20-Poly1305 AEAD. */
  public fun supportsChaCha20Poly1305(): Boolean
  public fun chacha20Poly1305Encrypt(
      key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      plaintext: ByteArray,
  ): ByteArray?
  public fun chacha20Poly1305Decrypt(
      key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      ciphertextWithTag: ByteArray,
  ): ByteArray?
}

/**
 * Sets the platform-native crypto provider.
 * Call this once at app startup from Swift, Java, or Kotlin:
 * ```swift
 * // App.swift (in the consuming iOS app)
 * KMP.setCryptoProvider(iOSCryptoKitProvider())
 * ```
 *
 * If never called, the library uses C-API interop (Part 1) + pure-K fallback.
 */
public expect fun setCryptoProvider(provider: CryptoProvider?)
```

### Step 2: Wire the dispatch in iosMain actuals

The dispatch logic lives in `iosMain`, not `commonMain`. The thin iosMain actuals
delegate to `CryptoBridge.kt` (provider → C-API → null) via the elvis operator,
then fall back to the corresponding `*PureK` object on null. Because the detekt
`ConstantTimeRule` (ADR-0003) is file-scoped on `@Secret` parameters, all branching
lives in the bridge file which contains no `@Secret` params:

```kotlin
// X25519.kt (iosMain actual)
actual fun compute(@Secret scalar: ByteArray, @Secret u: ByteArray): ByteArray =
    x25519Native(scalar, u) ?: X25519PureK.compute(scalar, u)

// Ed25519.kt (iosMain actual)
actual fun sign(@Secret secretKey: ByteArray, message: ByteArray): ByteArray =
    ed25519SignNative(secretKey, message) ?: Ed25519PureK.sign(secretKey, message)

// ChaCha20Poly1305.kt (iosMain actual)
actual fun encrypt(@Secret key: ByteArray, message: ByteArray): ByteArray =
    chacha20Poly1305EncryptNative(key, message) ?: ChaCha20Poly1305PureK.encrypt(key, message)
```

On JVM/Android targets, the actuals delegate to the JCA bridge (CryptoBridge.kt) with the same provider→native→PureK fallback. Only iOS uses the direct C-API path without the CryptoKit provider.

### Step 3: iOS expect/actual

```kotlin
// iosMain: stores the injected provider (default null)
internal var cryptoProvider: CryptoProvider? = null

actual fun setCryptoProvider(provider: CryptoProvider?) {
  cryptoProvider = provider
}
```

```kotlin
// jvmMain / androidMain: also stores the provider (JCA/Keystore backend)
actual fun setCryptoProvider(provider: CryptoProvider?) {
  cryptoProvider = provider
}
```

### Step 4: Swift implementation in the consuming app

```swift
// App.swift (in the consuming iOS app — NOT in this library)
import CryptoKit
import Shared

class CryptoKitProvider: NSObject, CryptoProvider {

  func supportsX25519() -> Bool { true }

  func x25519(scalar: KotlinByteArray, u: KotlinByteArray) -> KotlinByteArray? {
    // CryptoKit Curve25519.KeyAgreement
    guard let privateKey = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar.toData()),
          let publicKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: u.toData())
    else { return nil }
    guard let shared = try? privateKey.sharedSecretFromKeyExchange(with: publicKey)
    else { return nil }
    return shared.data.toKotlinByteArray()
  }

  func supportsEd25519() -> Bool { true }

  func ed25519PublicKeyFromPrivate(privateKey: KotlinByteArray) -> KotlinByteArray? {
    guard let key = try? Ed25519.PrivateKey(rawRepresentation: privateKey.toData())
    else { return nil }
    return key.publicKey.rawRepresentation.toKotlinByteArray()
  }

  func ed25519Sign(privateKey: KotlinByteArray, message: KotlinByteArray) -> KotlinByteArray? {
    guard let key = try? Ed25519.PrivateKey(rawRepresentation: privateKey.toData())
    else { return nil }
    return try? key.signature(for: message.toData()).toData().toKotlinByteArray()
  }

  func ed25519Verify(publicKey: KotlinByteArray, message: KotlinByteArray,
                    signature: KotlinByteArray) -> Bool {
    guard let key = try? Ed25519.PublicKey(rawRepresentation: publicKey.toData()),
          let sig = try? Ed25519.Signature(rawRepresentation: signature.toData())
    else { return false }
    return key.verify(signature: sig, for: message.toData())
  }

  func supportsChaCha20Poly1305() -> Bool { true }

  func chacha20Poly1305Encrypt(key: KotlinByteArray, nonce: KotlinByteArray,
                               aad: KotlinByteArray, plaintext: KotlinByteArray) -> KotlinByteArray? {
    let symmetricKey = SymmetricKey(data: key.toData())
    let nonce = try! ChaChaPoly.Nonce(rawRepresentation: nonce.toData())
    let sealedBox = try! ChaChaPoly.seal(plaintext.toData(), using: symmetricKey,
                                         nonce: nonce, authenticating: aad.toData())
    return sealedBox.combined?.toKotlinByteArray()
  }

  func chacha20Poly1305Decrypt(key: KotlinByteArray, nonce: KotlinByteArray,
                               aad: KotlinByteArray, ciphertextWithTag: KotlinByteArray) -> KotlinByteArray? {
    let symmetricKey = SymmetricKey(data: key.toData())
    let nonce = try! ChaChaPoly.Nonce(rawRepresentation: nonce.toData())
    let sealedBox = try! ChaChaPoly.SealedBox(combined: ciphertextWithTag.toData())
    return try? sealedBox.decrypt(authenticatedWith: symmetricKey,
                                  nonce: nonce, authenticating: aad.toData()).toKotlinByteArray()
  }
}

// At app startup:
@main
struct MyApp: App {
  init() {
    setCryptoProvider(CryptoKitProvider())
  }
  // ...
}
```

### Security best practice: keys stay in Swift

Per the user's guidance, the consuming app should store CryptoKit private keys
in the iOS Keychain / Secure Enclave. The `CryptoProvider` receives raw
key bytes from the library (e.g., an Ed25519 seed), but the app can choose to
import them into Secure Enclave-backed `SecKey` objects instead and never
export them. The library only deals with raw bytes at the interface boundary;
key lifecycle is the app's responsibility.

## Relationship between the two parts

```
commonMain:  X25519.compute(scalar, u)
                │
                ├─ iOS + CryptoKit provider injected? → call provider.x25519()
                │   (Swift-side CryptoKit + Secure Enclave)
                │
                └─ Otherwise: iosMain actual → C-API (SecKeyCopyKeyExchange)
                                      └─ API unavailable? → X25519PureK (commonMain)
```

The C-API path (Part 1) is the **default** on iOS — no app integration needed.
The CryptoKit provider path (Part 2) is **optional** — consuming apps opt in
when they need Secure Enclave integration.

## Build configuration (combined)

| Change | Location | Required? |
|---|---|---|
| Update `X25519.kt`, `Ed25519.kt`, `ChaCha20Poly1305.kt` in `iosMain` to use C-API interop | `crypto/src/iosMain/...` | Yes (Part 1) |
| Add `CryptoProvider.kt` interface + `setCryptoProvider` expect/actual | `crypto/src/{commonMain,iosMain,jvmMain,androidMain}/...` | Yes (Part 2) |
| `.def` file for CryptoKit | N/A | **No** — CryptoKit is Swift-only, not cinterop-able |
| `cInterop` Gradle block | `crypto/build.gradle.kts` | No — `platform.*` bindings are prebuilt |
| Re-enable iOS test tasks | `crypto/build.gradle.kts` | Recommended — validates C-API path on simulator |

## Testing strategy

1. **Wycheproof vectors** (ADR-0003): add iOS simulator-targeted Wycheproof test
   source sets alongside the existing `jvmTest` resources. The `commonTest`
   timing harness already exists.
2. **InteropHarnessTest**: existing class compares dispatch objects to
   `*PureK` — automatically verifies C-API consistency on iOS once actuals
   we wire them up.
3. **KAT vectors**: RFC 7748 §5.2, RFC 8032 §7, RFC 8439 §2.9.2 — add to
   existing test classes.
4. **iOS test execution**: `build.gradle.kts` currently disables `ios*Test`
   tasks. Re-enable for the simulator so CI validates the native path.
   Requires macOS CI runner.

## Minimum iOS version

| Primitive | Native API | Min iOS | Fallback |
|---|---|---|---|
| SHA-256 | `CC_SHA256` | any | — (already native) |
| SHA-512 | `CC_SHA512` | any | — (already native) |
| HMAC-SHA256 | `CCHmac` | any | — (already native) |
| X25519 | `SecKeyCopyKeyExchange` | 14.0 | `X25519PureK` |
| Ed25519 | `SecKeyCreateSignature/Verify` | 14.0 | `Ed25519PureK` |
| ChaCha20-Poly1305 | CryptoKit provider only (no CommonCrypto C API) | — | `ChaCha20Poly1305PureK` |
| HKDF | `CCHmac` (HMAC-SHA256) | any | `HKDF_SHA256PureK` |
| CSPRNG | `SecRandomCopyBytes` | any | — (already native) |

# signum Pure-Kotlin Crypto Audit

## Conclusion

**pure_k_crypto_found: no** — No pure-Kotlin crypto fallback module exists in a-sit-plus/signum. All cryptographic primitives (X25519, Ed25519, ChaCha20-Poly1305, HKDF, HMAC, SHA-256) delegate to platform-native crypto on every target platform. The only exception is a standalone SHA-256 utility in `indispensable-josef`, but it is not a general-purpose crypto primitive module.

## Evidence

### Modules surveyed

| Module | Role | Crypto delegation |
|--------|------|-------------------|
| `indispensable` | Core crypto interfaces (Digest, HMAC, KDF, SymmetricEncryptionAlgorithm, SealedBox, Signer, Verifier) | All platform-specific `actual` implementations delegate to JCA / CommonCrypto / Android KeyStore / iOS Keychain |
| `indispensable-josef` | JWS/JWE/JWK serialization + JOSE algorithms | SHA-256 utility (pure Kotlin) + JCA delegation for signing |
| `indispensable-cosef` | COSE format/serialization | Delegates to `indispensable` for crypto |
| `indispensable-asn1` | ASN.1 encoding/decoding | No crypto |
| `indispensable-oids` | OID definitions | No crypto |
| `supreme` | High-level crypto DSL (HPKE, KDF, MAC, Signer, Encryptor, Decryptor) | All platform-specific `actual` implementations delegate to JCA / CommonCrypto / Android KeyStore / iOS Keychain |
| `supreme/ecmath` | RFC9380 hash-to-curve, ModularBigInteger EC math | Uses `Digest.digest()` which delegates to platform crypto |

### Primitive-by-primitive classification

| Primitive | Pure-Kotlin? | File(s) | Classification |
|-----------|-------------|---------|----------------|
| SHA-256 | **YES** (standalone utility) | `indispensable-josef/src/commonMain/kotlin/at/asitplus/signum/indispensable/josef/io/sha256.kt` | Pure-Kotlin arithmetic (hand-rolled, public domain port of Brad Conte's C code). Not a general-purpose crypto module. |
| SHA-256 (general) | NO | `supreme/src/androidMain/.../hash/DigestImpl.kt` | `java.security.MessageDigest` |
| SHA-256 (general) | NO | `supreme/src/jvmMain/.../hash/DigestImpl.kt` | `java.security.MessageDigest` |
| SHA-256 (general) | NO | `supreme/src/iosMain/.../hash/DigestImpl.kt` | `platform.CoreCrypto.CC_SHA256_*` |
| HMAC | NO | `supreme/src/commonMain/.../mac/MAC.kt` | Pure-Kotlin HMAC construction, but calls `Digest.digest()` which delegates to platform crypto |
| HKDF | NO | `supreme/src/commonMain/.../kdf/KDF.kt` | Pure-Kotlin HKDF logic, but calls `HMAC.mac()` and `Digest.digest()` which delegate to platform crypto |
| PBKDF2 | NO | `supreme/src/commonMain/.../kdf/KDF.kt` | Pure-Kotlin PBKDF2 logic, but calls `Digest.digest()` which delegates |
| SCrypt | NO | `supreme/src/commonMain/.../kdf/KDF.kt` | Pure-Kotlin SCrypt logic, but calls `Digest.digest()` which delegates |
| ChaCha20-Poly1305 | NO | `supreme/src/androidJvmMain/.../symmetric/ChaCha.jca.kt` | `javax.crypto.Cipher` ("ChaCha20-Poly1305") |
| ChaCha20-Poly1305 | NO | `supreme/src/iosMain/.../symmetric/ChaCha.ios.kt` | Swift interop (`ChaCha.encrypt/decrypt`) |
| AES-GCM | NO | `supreme/src/androidJvmMain/.../symmetric/AES.jca.kt` | `javax.crypto.Cipher` ("AES/GCM/NoPadding") |
| AES-GCM | NO | `supreme/src/iosMain/.../symmetric/AES.ios.kt` | `platform.CoreCrypto.CCCrypt` |
| X25519 | NO | — | Not implemented anywhere in pure Kotlin |
| Ed25519 | NO | — | Not implemented anywhere in pure Kotlin |
| ECDSA (NIST curves) | NO | `supreme/src/androidMain/.../sign/EphemeralKeysImpl.kt` | `java.security.KeyPairGenerator` + `javax.crypto.Signature` |
| ECDSA (NIST curves) | NO | `supreme/src/iosMain/.../sign/EphemeralKeysImpl.kt` | `platform.Security.SecKeyCreateRandomKey` + `SecKeyCreateSignature` |
| RSA | NO | `supreme/src/androidJvmMain/.../asymmetric/RSA.jca.kt` | `javax.crypto.Cipher` + `java.security.Signature` |
| RSA | NO | `supreme/src/iosMain/.../asymmetric/RSA.ios.kt` | `platform.Security.SecKeyCreateSignature` |
| Key agreement (ECDH) | NO | `supreme/src/androidMain/.../sign/EphemeralKeysImpl.kt` | `javax.crypto.KeyAgreement` |
| Key agreement (ECDH) | NO | `supreme/src/iosMain/.../sign/EphemeralKeysImpl.kt` | `platform.Security.SecKeyCopyKey` |
| Key generation | NO | `supreme/src/androidMain/.../sign/EphemeralKeysImpl.kt` | `java.security.KeyPairGenerator` |
| Key generation | NO | `supreme/src/jvmMain/.../os/JKSProvider.kt` | `java.security.KeyStore` |
| Key generation | NO | `supreme/src/iosMain/.../sign/EphemeralKeysImpl.kt` | `platform.Security.SecKeyCreateRandomKey` |

### Key findings

1. **No pure-Kotlin X25519/Ed25519**: signum does not implement these algorithms in pure Kotlin arithmetic anywhere.
2. **No pure-Kotlin ChaCha20-Poly1305**: All ChaCha20-Poly1305 implementations delegate to JCA (Android/JVM) or Swift (iOS).
3. **No pure-Kotlin HKDF/HMAC**: The HKDF and HMAC logic in `supreme/kdf/KDF.kt` and `supreme/mac/MAC.kt` is pure Kotlin, but they call `Digest.digest()` which is a platform-specific `actual` function delegating to `java.security.MessageDigest`, `javax.crypto.Cipher`, or `CommonCrypto`.
4. **No pure-Kotlin crypto fallback module**: There is no module that provides a pure-Kotlin implementation of any cryptographic primitive as a fallback when platform crypto is unavailable.
5. **One pure-Kotlin SHA-256**: `indispensable-josef/io/sha256.kt` is a hand-rolled SHA-256 implementation used exclusively for JWS signing in the `indispensable-josef` module. It is not a general-purpose crypto primitive module and is not used by `indispensable` or `supreme`.
6. **All `doDigest` actuals delegate**: Every platform-specific `doDigest` implementation (`androidMain`, `jvmMain`, `iosMain`) delegates to a platform-native hash function.
7. **All `initCipher` actuals delegate**: Every platform-specific `initCipher` implementation delegates to `javax.crypto.Cipher` (Android/JVM) or `CommonCrypto`/Swift (iOS).

## Source URLs

- Repository: <https://github.com/a-sit-plus/signum>
- SHA-256 (pure Kotlin): <https://github.com/a-sit-plus/signum/blob/main/indispensable-josef/src/commonMain/kotlin/at/asitplus/signum/indispensable/josef/io/sha256.kt>
- HMAC (delegates to platform): <https://github.com/a-sit-plus/signum/blob/main/supreme/src/commonMain/kotlin/at/asitplus/signum/supreme/mac/MAC.kt>
- HKDF (delegates to platform): <https://github.com/a-sit-plus/signum/blob/main/supreme/src/commonMain/kotlin/at/asitplus/signum/supreme/kdf/KDF.kt>
- Digest expect/actual: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/commonMain/kotlin/at/asitplus/signum/supreme/hash/DigestExtensions.kt>
- DigestImpl Android: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/androidMain/kotlin/at/asitplus/signum/supreme/hash/DigestImpl.kt>
- DigestImpl JVM: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/jvmMain/kotlin/at/asitplus/signum/supreme/hash/DigestImpl.kt>
- DigestImpl iOS: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/iosMain/kotlin/at/asitplus/signum/supreme/hash/DigestImpl.kt>
- AES JCA: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/androidJvmMain/kotlin/at/asitplus/signum/supreme/symmetric/AES.jca.kt>
- ChaCha JCA: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/androidJvmMain/kotlin/at/asitplus/signum/supreme/symmetric/ChaCha.jca.kt>
- Encryptor JCA: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/androidJvmMain/kotlin/at/asitplus/signum/supreme/symmetric/Encryptor.jca.kt>
- AES iOS: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/iosMain/kotlin/at/asitplus/signum/supreme/symmetric/AES.ios.kt>
- ChaCha iOS: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/iosMain/kotlin/at/asitplus/signum/supreme/symmetric/ChaCha.ios.kt>
- AndroidKeyStoreProvider: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/androidMain/kotlin/at/asitplus/signum/supreme/os/AndroidKeyStoreProvider.kt>
- IosKeychainProvider: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/iosMain/kotlin/at/asitplus/signum/supreme/os/IosKeychainProvider.kt>
- JKSProvider: <https://github.com/a-sit-plus/signum/blob/main/supreme/src/jvmMain/kotlin/at/asitplus/signum/supreme/os/JKSProvider.kt>
- RFC9380 (pure Kotlin math, but uses platform Digest): <https://github.com/a-sit-plus/signum/blob/main/supreme/src/commonMain/kotlin/at/asitplus/signum/ecmath/RFC9380.kt>
- SymmetricEncryptionAlgorithm: <https://github.com/a-sit-plus/signum/blob/main/indispensable/src/commonMain/kotlin/at/asitplus/signum/indispensable/symmetric/SymmetricEncryptionAlgorithm.kt>

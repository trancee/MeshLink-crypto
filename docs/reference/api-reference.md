# API Reference

> **Reference.** This page documents the public API. It is neutral and factual. For background on design decisions, see [Architecture](../explanation/architecture.md) and [Constant-Time Discipline](../explanation/constant-time.md).

## Package

`ch.trancee.meshlink.crypto`

## Design principles

All public entry points follow four rules (see [ADR-0005](../adr/0005-api-surface.md)):

- **Typed key handles.** Secret keys use `SecretKey`, `PrivateKey`, and `PublicKey`. These are `AutoCloseable` types that zero their backing byte array on `close()`. The public API never accepts a raw `ByteArray` for key material.
- **Internal nonce.** ChaCha20-Poly1305 generates a fresh 96-bit nonce per call. Callers never supply a nonce.
- **No-throw.** Operations return `Result<T>`. Errors are values, not exceptions.
- **Transparent fallback.** Each primitive selects its provider per-primitive without caller intervention.

## Key handle types

### `SecretKey(material: ByteArray) : AutoCloseable`

A symmetric secret key handle.

| Member | Signature | Description |
|---|---|---|
| `bytes` | `ByteArray` (getter) | Returns a defensive copy of the key bytes. |
| `close()` | `(): Unit` | Zeroes the backing byte array. Use `use { }` to scope the handle. |

Example:
```kotlin
val key = SecretKey(generateKeyMaterial())
try {
    val encrypted = Crypto.chacha20Poly1305Encrypt(key, plaintext)
} finally {
    key.close()
}
// Or: SecretKey(key).use { key -> Crypto.chacha20Poly1305Encrypt(key, plaintext) }
```

### `PrivateKey(material: ByteArray) : AutoCloseable`

An asymmetric private key handle.

| Member | Signature | Description |
|---|---|---|
| `bytes` | `ByteArray` (getter) | Returns a defensive copy of the key bytes. |
| `close()` | `(): Unit` | Zeroes the backing byte array. |

### `PublicKey(material: ByteArray) : AutoCloseable`

An asymmetric public key handle.

| Member | Signature | Description |
|---|---|---|
| `bytes` | `ByteArray` (getter) | Returns a defensive copy of the key bytes. |
| `close()` | `(): Unit` | Zeroes the backing byte array. |

## `Crypto` — unified facade

```kotlin
public object Crypto
```

A single entry point that delegates to all primitive facade objects. Preferred for new code.

### Hashing

```kotlin
fun sha256(message: ByteArray): Result<ByteArray>
```
Computes SHA-256. Returns 32 bytes.

```kotlin
fun sha512(message: ByteArray): Result<ByteArray>
```
Computes SHA-512. Returns 64 bytes.

### HMAC

```kotlin
fun hmacSha256(key: SecretKey, message: ByteArray): Result<ByteArray>
```
Computes HMAC-SHA256. Returns 32 bytes.

```kotlin
fun verifyHmacSha256(key: SecretKey, message: ByteArray, tag: ByteArray): Result<Boolean>
```
Verifies an HMAC-SHA256 tag. Uses constant-time comparison.

### HKDF

```kotlin
fun hkdfSha256(
    ikm: ByteArray,
    salt: ByteArray,
    info: ByteArray,
    outputLength: Int,
): Result<ByteArray>
```
Runs full HKDF-SHA256 (extract + expand). `ikm` is secret. `salt` and `info` are public per RFC 5869. `outputLength` must be at most 8160 (255 × 32).

```kotlin
fun extract(ikm: ByteArray, salt: ByteArray): Result<ByteArray>
```
HKDF-Extract: `PRK = HMAC-SHA256(salt, IKM)`. Returns 32 bytes.

```kotlin
fun expand(prk: ByteArray, info: ByteArray, outputLength: Int): Result<ByteArray>
```
HKDF-Expand. Returns `outputLength` bytes.

### Key agreement

```kotlin
fun x25519(scalar: PrivateKey, u: PublicKey): Result<ByteArray>
```
Computes the X25519 shared secret. Returns 32 bytes.

### Signatures

```kotlin
fun ed25519Sign(secretKey: PrivateKey, message: ByteArray): Result<ByteArray>
```
Signs a message with Ed25519. Returns 64 bytes.

```kotlin
fun ed25519Verify(
    publicKey: PublicKey,
    message: ByteArray,
    signature: ByteArray,
): Result<Boolean>
```
Verifies an Ed25519 signature.

### AEAD

```kotlin
fun chacha20Poly1305Encrypt(key: SecretKey, message: ByteArray): Result<ByteArray>
```
Encrypts with ChaCha20-Poly1305. The nonce is generated internally. Output format: `nonce(12) || ciphertext || tag(16)`.

```kotlin
fun chacha20Poly1305Decrypt(
    key: SecretKey,
    ciphertext: ByteArray,
): Result<ByteArray?>
```
Decrypts and authenticates. `ciphertext` must be `nonce(12) || ciphertext || tag(16)`. Returns the plaintext on success. Returns `null` (inside `Result.success`) if authentication fails. Returns `Result.failure` if the input is malformed (wrong length).

## Per-primitive facade objects

Each facade object below mirrors the corresponding `Crypto` function. They remain public for backward compatibility. Code may use either style.

### `Hasher`
```kotlin
object Hasher {
    fun sha256(message: ByteArray): Result<ByteArray>
    fun sha512(message: ByteArray): Result<ByteArray>
}
```

### `Authenticator`
```kotlin
object Authenticator {
    fun hmacSha256(key: SecretKey, message: ByteArray): Result<ByteArray>
    fun verify(key: SecretKey, message: ByteArray, tag: ByteArray): Result<Boolean>
}
```

### `Kdf`
```kotlin
object Kdf {
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, outputLength: Int): Result<ByteArray>
    fun extract(ikm: ByteArray, salt: ByteArray): Result<ByteArray>
    fun expand(prk: ByteArray, info: ByteArray, outputLength: Int): Result<ByteArray>
}
```

### `KeyExchange`
```kotlin
object KeyExchange {
    fun x25519(scalar: PrivateKey, u: PublicKey): Result<ByteArray>
}
```

### `Signer`
```kotlin
object Signer {
    fun ed25519Sign(secretKey: PrivateKey, message: ByteArray): Result<ByteArray>
    fun ed25519Verify(publicKey: PublicKey, message: ByteArray, signature: ByteArray): Result<Boolean>
}
```

### `Aead`
```kotlin
object Aead {
    fun chacha20Poly1305Encrypt(key: SecretKey, message: ByteArray): Result<ByteArray>
    fun chacha20Poly1305Decrypt(key: SecretKey, ciphertext: ByteArray): Result<ByteArray?>
}
```

## Optional native provider injection

### `CryptoProvider`

```kotlin
public interface CryptoProvider
```

An optional interface that consuming apps can implement to inject platform-native crypto (CryptoKit on iOS, custom JCA provider on JVM/Android). Each method returns `null` (or `false` for verify) when the provider cannot handle the operation. The library then falls back to its next path.

| Method | Returns |
|---|---|
| `supportsX25519(): Boolean` | Whether the provider handles X25519. |
| `x25519(scalar: ByteArray, u: ByteArray): ByteArray?` | 32-byte shared secret, or `null`. |
| `supportsEd25519(): Boolean` | Whether the provider handles Ed25519. |
| `ed25519PublicKeyFromPrivate(secretKey: ByteArray): ByteArray?` | 32-byte public key, or `null`. |
| `ed25519Sign(secretKey: ByteArray, message: ByteArray): ByteArray?` | 64-byte signature, or `null`. |
| `ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean?` | `true`/`false`, or `null` if unsupported. |
| `supportsChaCha20Poly1305(): Boolean` | Whether the provider handles ChaCha20-Poly1305. |
| `chacha20Poly1305Encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray?` | Ciphertext+tag, or `null`. |
| `chacha20Poly1305Decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertextWithTag: ByteArray): ByteArray?` | Plaintext, or `null`. |

### `setCryptoProvider(provider: CryptoProvider?)`

Sets the platform-native crypto provider. Pass `null` to clear. Call once at app startup. When no provider is set, the library uses its native C-API / JCA path or the pure-Kotlin fallback.

```swift
// iOS app startup
KMP.setCryptoProvider(CryptoKitProvider())
```

## Module version

```kotlin
fun moduleVersion(): String
```

Returns the current module version string (e.g. `0.1.0-SNAPSHOT`).

## Error handling

| Return type | Error case |
|---|---|
| `Result<ByteArray>` | `Result.failure` wraps the exception. |
| `Result<Boolean>` | `Result.failure` if the operation cannot proceed. |
| `Result<ByteArray?>` (AEAD decrypt) | `Result.success(null)` means authentication failed (the tag mismatch was detected). `Result.failure` means the input was malformed. |

All public functions wrap their calls in `runCatching`. No exceptions cross the Kotlin/Multiplatform boundary.

## Thread safety

All public primitives are stateless and thread-safe. Key handles (`SecretKey`, `PrivateKey`, `PublicKey`) are not thread-safe — scope each handle with `use { }` and call `close()` before another thread accesses it.

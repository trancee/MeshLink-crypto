# API Reference

> **Reference.** This page documents the public API. It states what each type and function does, what each parameter means, and when to use it. For step-by-step instructions, see the [How-to guides](../how-to/) and [Best Practices](../how-to/best-practices.md). For design rationale, see [Architecture](../explanation/architecture.md).

## Package

`ch.trancee.meshlink.crypto`

## Design principles

All public entry points follow four rules (see [ADR-0005](../adr/0005-api-surface.md)):

- **Typed key handles.** Secret keys use `SecretKey`, `PrivateKey`, and `PublicKey`. These are `AutoCloseable` types that zero their backing byte array on `close()`. The public API never accepts a raw `ByteArray` for key material.
- **Internal nonce.** ChaCha20-Poly1305 generates a fresh 96-bit nonce per call. Callers never supply a nonce.
- **No-throw.** Operations return `Result<T>`. Errors are values, not exceptions.
- **Transparent fallback.** Each primitive selects its provider per-primitive without caller intervention.

## Choosing an entry point

Use the **unified `Crypto` object** for new code. It delegates to the per-primitive facade objects without adding logic. The individual facade objects (`Hasher`, `Authenticator`, `Kdf`, `KeyExchange`, `Signer`, `Aead`) are equivalent entry points retained for backward compatibility.

| Operation | Use | Example |
|---|---|---|
| Hashing (SHA-256, SHA-512, SHAKE256, SHAKE128) | `Crypto.sha256()` / `Crypto.sha512()` / `Crypto.shake256()` / `Crypto.shake128()` or `Hasher` | `Crypto.sha256(data)` |
| HMAC | `Crypto.hmacSha256()` / `Crypto.verifyHmacSha256()` or `Authenticator` | `Crypto.hmacSha256(key, msg)` |
| Key derivation | `Crypto.hkdfSha256()` / `Crypto.extract()` / `Crypto.expand()` or `Kdf` | `Crypto.hkdfSha256(ikm, salt, info, 32)` |
| Key agreement | `Crypto.x25519()` / `Crypto.deriveX25519PublicKey()` or `KeyExchange` | `Crypto.x25519(scalar, u)`, `Crypto.deriveX25519PublicKey(key)` |
| Public key derivation | `Crypto.deriveX25519PublicKey()` / `Crypto.ed25519PublicKeyFromPrivate()` | `Crypto.deriveX25519PublicKey(key)`, `Crypto.ed25519PublicKeyFromPrivate(key)` |
| Signing | `Crypto.ed25519Sign()` / `Crypto.ed25519Verify()` / `Crypto.ed25519PublicKeyFromPrivate()` or `Signer` | `Crypto.ed25519Sign(key, msg)`, `Crypto.ed25519PublicKeyFromPrivate(key)` |
| Randomness | `Crypto.randomBytes()` | `Crypto.randomBytes(32)` |
| Authenticated encryption | `Crypto.chacha20Poly1305Encrypt()` / `Crypto.chacha20Poly1305Decrypt()` or `Aead` | `Crypto.chacha20Poly1305Encrypt(key, msg)`|

## Key handle types

### `SecretKey(material: ByteArray) : AutoCloseable`

A symmetric secret key handle. Use this for operations that need a symmetric key: HMAC, HKDF input, and ChaCha20-Poly1305 encryption/decryption.

| Member | Description |
|---|---|
| `material` (constructor) | The raw key bytes. Ownership transfers to the handle — the caller should zero their copy after construction. |
| `bytes` | Returns a defensive copy of the key bytes. Each call allocates a new array. |
| `close()` | Zeroes the backing byte array. Must be called before the handle goes out of scope, or use `use { }`. |

A 32-byte (256-bit) key is required for ChaCha20-Poly1305. Any length is valid for HMAC and HKDF-Extract.

### `PrivateKey(material: ByteArray) : AutoCloseable`

An asymmetric private key handle. Use this as input to X25519 key agreement and Ed25519 signing.

| Member | Description |
|---|---|
| `material` (constructor) | The raw private key bytes. For X25519, this is the 32-byte scalar. For Ed25519, this is the 32-byte seed. Ownership transfers to the handle. |
| `bytes` | Returns a defensive copy of the key bytes. |
| `close()` | Zeroes the backing byte array. |

### `PublicKey(material: ByteArray) : AutoCloseable`

An asymmetric public key handle. Use this as input to X25519 key agreement (the peer's public key) and Ed25519 verification.

| Member | Description |
|---|---|
| `material` (constructor) | The raw public key bytes. For X25519, this is the 32-byte u-coordinate. For Ed25519, this is the 32-byte public key. |
| `bytes` | Returns a defensive copy of the key bytes. |
| `close()` | Zeroes the backing byte array, even though public keys are not secret. |

## `Crypto` — unified entry point

```kotlin
public object Crypto
```

A single entry point that delegates to all primitive facade objects. Use this for new code.

### Hashing

```kotlin
fun sha256(message: ByteArray): Result<ByteArray>
```

Computes SHA-256 ([RFC 6234 §5.1](https://datatracker.ietf.org/doc/html/rfc6234#section-5.1)).

| Parameter | Description |
|---|---|
| `message` | The bytes to hash. Any length. |
| **Returns** | 32-byte digest on success; `Result.failure` on error. |

```kotlin
fun sha512(message: ByteArray): Result<ByteArray>
```

Computes SHA-512 ([RFC 6234 §5.2](https://datatracker.ietf.org/doc/html/rfc6234#section-5.2)).

| Parameter | Description |
|---|---|
| `message` | The bytes to hash. Any length. |
| **Returns** | 64-byte digest on success; `Result.failure` on error. |

```kotlin
fun shake256(message: ByteArray, outputLength: Int): Result<ByteArray>
```

Computes SHAKE256 (FIPS 202 §8.4), an extendable-output function (XOF) based on the Keccak-f[1600] permutation. Pure-Kotlin implementation with rate = 136 bytes and capacity = 512 bits.

| Parameter | Description |
|---|---|
| `message` | The bytes to hash. Any length. |
| `outputLength` | The number of output bytes to squeeze. Any positive value. |
| **Returns** | `outputLength` bytes of output on success; `Result.failure` on error. |

\`\`\`kotlin
fun shake128(message: ByteArray, outputLength: Int): Result<ByteArray>
\`\`\`

Computes SHAKE128 (FIPS 202 §8.3), an extendable-output function (XOF) based on the Keccak-f[1600] permutation. Pure-Kotlin implementation with rate = 168 bytes and capacity = 256 bits.

| Parameter | Description |
|---|---|
| `message` | The bytes to hash. Any length. |
| `outputLength` | The number of output bytes to squeeze. Any positive value. |
| **Returns** | `outputLength` bytes of output on success; `Result.failure` on error. |

### HMAC

```kotlin
fun hmacSha256(key: SecretKey, message: ByteArray): Result<ByteArray>
```

Computes HMAC-SHA256 ([RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104)). Produces an authentication tag.

| Parameter | Description |
|---|---|
| `key` | The secret authentication key. Any length; keys longer than 64 bytes are first SHA-256-hashed per RFC 2104 §3. |
| `message` | The message to authenticate. Any length. |
| **Returns** | 32-byte tag on success; `Result.failure` on error. |

```kotlin
fun verifyHmacSha256(
    key: SecretKey,
    message: ByteArray,
    tag: ByteArray,
): Result<Boolean>
```

Verifies an HMAC-SHA256 tag. Uses constant-time comparison internally (no early exit).

| Parameter | Description |
|---|---|
| `key` | The secret authentication key. Must match the key used to produce the tag. |
| `message` | The authenticated message. |
| `tag` | The candidate tag to verify. Any length; a length mismatch results in `false`, not an error. |
| **Returns** | `Result.success(true)` if valid, `Result.success(false)` if invalid. |

### HKDF

```kotlin
fun hkdfSha256(
    ikm: ByteArray,
    salt: ByteArray,
    info: ByteArray,
    outputLength: Int,
): Result<ByteArray>
```

Runs full HKDF-SHA256 ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)) — Extract then Expand. Use this when deriving session keys from a shared secret.

| Parameter | Description |
|---|---|
| `ikm` | The secret input keying material. Any length. |
| `salt` | The public salt. Use zeros or an empty array for the default salt (a string of HashLen zero bytes). |
| `info` | The public context string. Use a distinct string for each key purpose (key separation). |
| `outputLength` | Number of output bytes. Must be at most 8160 (255 × 32). |
| **Returns** | `outputLength` bytes of derived keying material on success. |

```kotlin
fun extract(ikm: ByteArray, salt: ByteArray): Result<ByteArray>
```

HKDF-Extract only: `PRK = HMAC-SHA256(salt, IKM)`. Use this when you need the intermediate PRK before calling Expand.

```kotlin
fun expand(prk: ByteArray, info: ByteArray, outputLength: Int): Result<ByteArray>
```

HKDF-Expand only: `OKM = Expand(PRK, info, L)`. Use this after calling `extract` to derive multiple keys from the same PRK.

### Key agreement

```kotlin
fun x25519(scalar: PrivateKey, u: PublicKey): Result<ByteArray>
```

Computes the X25519 shared secret ([RFC 7748 §5](https://datatracker.ietf.org/doc/html/rfc7748#section-5)).

| Parameter | Description |
|---|---|
| `scalar` | The 32-byte private scalar (little-endian). |
| `u` | The 32-byte peer public u-coordinate (little-endian). |
| **Returns** | 32-byte shared secret on success; `Result.failure` on error. |

### Public key derivation

```kotlin
fun deriveX25519PublicKey(privateKey: PrivateKey): Result<ByteArray>
```

Derives the X25519 public key from a private scalar: `publicKey = scalar * BASEPOINT` ([RFC 7748 §5](https://datatracker.ietf.org/doc/html/rfc7748#section-5)).

| Parameter | Description |
||---|---|
| `privateKey` | The 32-byte private scalar (little-endian). |
| **Returns** | 32-byte public u-coordinate on success; `Result.failure` on error. |

```kotlin
fun ed25519PublicKeyFromPrivate(secretKey: PrivateKey): Result<ByteArray>
```

Derives the Ed25519 public key from the 32-byte seed ([RFC 8032 §5.1.5](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5)).

| Parameter | Description |
||---|---|
| `secretKey` | The 32-byte Ed25519 seed. |
| **Returns** | 32-byte public key on success; `Result.failure` on error. |

### Signatures

```kotlin
fun ed25519Sign(secretKey: PrivateKey, message: ByteArray): Result<ByteArray>
```

Signs a message with Ed25519 ([RFC 8032 §5.1](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1)).

| Parameter | Description |
|---|---|
| `secretKey` | The 32-byte Ed25519 seed. |
| `message` | The message to sign. Any length. |
| **Returns** | 64-byte signature on success; `Result.failure` on error. |

```kotlin
fun ed25519Verify(
    publicKey: PublicKey,
    message: ByteArray,
    signature: ByteArray,
): Result<Boolean>
```

Verifies an Ed25519 signature.

| Parameter | Description |
|---|---|
| `publicKey` | The 32-byte Ed25519 public key. |
| `message` | The signed message. |
| `signature` | The 64-byte signature to verify. |
| **Returns** | `Result.success(true)` if valid; `Result.success(false)` if invalid. |

### AEAD

```kotlin
fun chacha20Poly1305Encrypt(key: SecretKey, message: ByteArray): Result<ByteArray>
```

Encrypts with ChaCha20-Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) §2.8). A fresh 96-bit nonce is generated internally.

| Parameter | Description |
|---|---|
| `key` | The 32-byte (256-bit) secret key. |
| `message` | The plaintext to encrypt. Any length (including empty). |
| **Returns** | `nonce(12) + ciphertext + tag(16)` on success. |

```kotlin
fun chacha20Poly1305Decrypt(
    key: SecretKey,
    ciphertext: ByteArray,
): Result<ByteArray?>
```

Decrypts and authenticates. The input must have the format produced by `chacha20Poly1305Encrypt`: `nonce(12) + ciphertext + tag(16)`.

| Parameter | Description |
|---|---|
| `key` | The 32-byte (256-bit) secret key. Must match the key used to encrypt. |
| `ciphertext` | The blob from `chacha20Poly1305Encrypt`. Must be at least 28 bytes (12 nonce + 16 tag). |
| **Returns** | `Result.success(plaintext)` if the tag verifies. `Result.success(null)` if authentication fails (the tag did not match — possible tampering). `Result.failure` if the input is malformed (wrong length). |

### Randomness

```kotlin
fun randomBytes(size: Int): ByteArray
```

Generates `size` cryptographically secure random bytes from the platform CSPRNG. Use this for generating private key seeds (32 bytes for Ed25519/X25519) and symmetric keys (32 bytes for ChaCha20-Poly1305).

| Parameter | Description |
||---|---|
| `size` | The number of bytes to generate. |
| **Returns** | A byte array of `size` random bytes. |

```kotlin
val privateKey = PrivateKey(randomBytes(32))
```

## Optional native provider injection

### `CryptoProvider`

```kotlin
public interface CryptoProvider
```

An optional interface that consuming apps can implement to inject platform-native crypto (CryptoKit on iOS, custom JCA provider on JVM/Android). Each method returns `null` (or `false` for verify) when the provider cannot handle the operation. The library then falls back to its native path or the pure-Kotlin implementation.

Do not set a provider unless you need features the default native path cannot provide (for example, Secure Enclave key storage on iOS). See [ADR-0002](../adr/0002-fallback-strategy.md) and the [dependency-inversion proposal](../proposals/0001-cryptokit-ios-native.md).

| Method | Description |
|---|---|
| `supportsX25519()` | Returns `true` if the provider handles X25519 key agreement. |
| `x25519(scalar, u)` | Returns the 32-byte shared secret, or `null` if unsupported. |
| `x25519PublicKeyFromPrivate(scalar)` | Returns the 32-byte public u-coordinate derived from the 32-byte scalar, or `null`. |
| `supportsEd25519()` | Returns `true` if the provider handles Ed25519 signing and verification. |
| `ed25519PublicKeyFromPrivate(secretKey)` | Returns the 32-byte public key derived from the 32-byte seed, or `null`. |
| `ed25519Sign(secretKey, message)` | Returns the 64-byte signature, or `null`. |
| `ed25519Verify(publicKey, message, signature)` | Returns `true` if valid, `false` if invalid, or `null` if unsupported. |
| `supportsChaCha20Poly1305()` | Returns `true` if the provider handles ChaCha20-Poly1305 AEAD. |
| `chacha20Poly1305Encrypt(key, nonce, aad, plaintext)` | Returns `ciphertext + tag(16)`, or `null`. The provider must generate or receive a unique 12-byte nonce. |
| `chacha20Poly1305Decrypt(key, nonce, aad, ciphertextWithTag)` | Returns the plaintext, or `null` if the tag fails. |

### `setCryptoProvider(provider: CryptoProvider?)`

Sets the platform-native crypto provider. Pass `null` to clear. Call this once at application startup before any crypto operations.

```swift
// iOS app startup
KMP.setCryptoProvider(CryptoKitProvider())
```

When no provider is set, the library uses its native C-API / JCA path or the pure-Kotlin fallback.

## Error handling

| Return type | `Result.success` | `Result.failure` |
|---|---|---|
| `Result<ByteArray>` | The output bytes | The operation raised an exception |
| `Result<Boolean>` | `true` (valid) or `false` (invalid) | The operation could not proceed |
| `Result<ByteArray?>` (AEAD decrypt) | Plaintext (tag verified) or `null` (tag failed) | The input was malformed (e.g. wrong length) |

All public functions wrap their calls in `runCatching`. No exceptions cross the Kotlin/Multiplatform boundary.

### AEAD authentication failure vs. malformed input

A `null` return inside `Result.success` from `chacha20Poly1305Decrypt` means the Poly1305 tag did not verify. This is a security-relevant event: the ciphertext was tampered with or the wrong key was used. A `Result.failure` means the input length was invalid — a programming error, not an attack. See [Best Practices](../how-to/best-practices.md) for handling both cases.

## Thread safety

All public primitives are stateless and thread-safe. Key handles (`SecretKey`, `PrivateKey`, `PublicKey`) are not thread-safe — scope each handle with `use { }` and call `close()` before another thread accesses the same handle.

## Module version

```kotlin
fun moduleVersion(): String
```

Returns the current module version string (e.g. `0.1.1`).

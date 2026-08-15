# How to: Follow Security and Usage Best Practices

> **How-to guide.** This guide lists the security and usage best practices for using this library correctly. It assumes you have read the [API Reference](../reference/api-reference.md) and [Architecture](../explanation/architecture.md). For background on the security model, see [Constant-Time Discipline](../explanation/constant-time.md).

## Key lifecycle

### Always scope key handles with `use`

`SecretKey`, `PrivateKey`, and `PublicKey` are `AutoCloseable`. Their backing byte arrays are zeroed on `close()`. Always use `use { }` to scope the lifetime of a key handle.

```kotlin
// Good
SecretKey(keyBytes).use { key ->
    Crypto.chacha20Poly1305Encrypt(key, plaintext)
}
// key bytes are zeroed here — out of scope

// Bad — key material lingers until GC
val key = SecretKey(keyBytes)
val encrypted = Crypto.chacha20Poly1305Encrypt(key, plaintext)
// key is not closed — bytes may linger in memory
```

### Zero your own key material after wrapping

When you create a key handle, the handle takes ownership of the byte array. If you still hold a reference to the original array, zero it yourself:

```kotlin
val keyBytes = ByteArray(32) { generateByte() }
try {
    SecretKey(keyBytes).use { key ->
        Crypto.chacha20Poly1305Encrypt(key, plaintext)
    }
} finally {
    keyBytes.fill(0)
}
```

## Error handling

### Never ignore `Result` failures

All public operations return `Result<T>`. A failed result means the operation did not complete. Do not silently discard failures.

```kotlin
// Good
val result = Crypto.sha256(data)
if (result.isFailure) {
    logger.error("hashing failed", result.exceptionOrNull())
}

// Better — fail fast in contexts that should not proceed
val digest = Crypto.sha256(data).getOrThrow()

// Bad — ignores a possible failure
val digest = Crypto.sha256(data).getOrDefault(ByteArray(32))
```

### Distinguish authentication failure from programming error

For AEAD decryption, `Result.success(null)` means the tag did not verify (the ciphertext was tampered with or the key is wrong). `Result.failure` means the input was malformed (wrong length, corrupted structure).

```kotlin
val result = Crypto.chacha20Poly1305Decrypt(key, ciphertext).getOrThrow()
when (result) {
    null -> throw SecurityException("Authentication failed — ciphertext may be tampered")
    else -> use(result)
}
```

## Key derivation

### Always derive keys through HKDF

Never use a raw X25519 shared secret directly as an encryption key. The shared secret is not uniformly distributed. Derive keys through HKDF first:

```kotlin
val sharedSecret = Crypto.x25519(scalar, u).getOrThrow() // 32 bytes
val sessionKey = Crypto.hkdfSha256(
    ikm = sharedSecret,
    salt = ByteArray(32), // 32 zero bytes — or use a random salt
    info = "my-app-session-key-v1".encodeToByteArray(),
    outputLength = 32,
).getOrThrow()
```

### Use context-specific `info` strings

The `info` parameter in HKDF binds derived keys to a specific context. Use distinct `info` strings for encryption keys, signing keys, and other key purposes. This prevents key substitution across contexts (key separation).

### Use unique salts for HKDF-Extract

If you reuse the same IKM across sessions, use a fresh random salt for each derivation. A static salt defeats the purpose of HKDF's extract step.

## Nonce management

### Trust the internal nonce

The library generates a fresh 96-bit nonce for every ChaCha20-Poly1305 encryption call. Never try to supply your own nonce. Never reuse a key with the same nonce — this breaks confidentiality and authentication entirely.

### If you inject a CryptoProvider

When you supply a `CryptoProvider` implementation, the `chacha20Poly1305Encrypt` method receives an explicit `nonce` parameter. Your provider implementation must generate a cryptographically random nonce of exactly 12 bytes. Never reuse a nonce with the same key.

## Key separation

### Use different keys for different purposes

Do not use the same key for encryption and authentication. Derive separate keys for each purpose using HKDF with distinct `info` strings:

```kotlin
val encKey = Crypto.hkdfSha256(master, salt, "encryption".encodeToByteArray(), 32).getOrThrow()
val authKey = Crypto.hkdfSha256(master, salt, "authentication".encodeToByteArray(), 32).getOrThrow()
```

## Ed25519 signing

### Verify before trusting

Always verify Ed25519 signatures with `Signer.ed25519Verify` before trusting any data signed by a third party. Verification is inexpensive — 64 KB of memory and a single scalar multiplication.

### Keep signing keys private

The Ed25519 private key is the 32-byte seed, not the public key. The public key can be shared freely. The private key must never leave the device. If you need hardware-backed key storage, inject a `CryptoProvider` backed by the Android Keystore or iOS Secure Enclave.

## X25519 key agreement

### Validate shared secrets

After an X25519 key agreement, check that the shared secret is not all zeros. An all-zero output indicates a weak or invalid public key (RFC 7748 §6.1). The pure-Kotlin implementation handles the u-coordinate clamping per RFC 7748 §5.2.

```kotlin
val shared = Crypto.x25519(scalar, u).getOrThrow()
require(shared.any { it != 0.toByte() }) { "Invalid shared secret — public key may be malicious" }
```

## Native provider injection

### Only inject if you need it

The library's native path (JCA, CommonCrypto, Security.framework) is used automatically when available. Only inject a `CryptoProvider` if you need features the native path cannot provide — such as Secure Enclave keys that never leave the hardware.

### Set it once at startup

Call `setCryptoProvider()` once at application startup, before any crypto operations. Do not change it at runtime.

## Testing and verification

### Treat CI as a smoke test

CI runs `./gradlew check` on macOS. This validates compilation, formatting, lint, coverage, and correctness vectors. It is not a substitute for local testing on your target platform.

### Run on your target platform

The pure-Kotlin path is tested on the JVM. If you target iOS or specific Android API levels, verify the native dispatch works on those platforms. Use the [interop harness tests](../reference/api-reference.md) as a pattern.

## See also

- [Constant-Time Discipline](../explanation/constant-time.md) — the security model behind the pure-Kotlin path
- [Architecture](../explanation/architecture.md) — how dispatch and fallback work
- [Supported Primitives](../reference/supported-primitives.md) — native availability per platform
- [ADR-0003](../adr/0003-verification-gates.md) — verification gates

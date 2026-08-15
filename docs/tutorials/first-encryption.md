# Tutorial: Encrypt and Decrypt Your First Message

> **Tutorial.** This hands-on lesson walks you through encrypting and decrypting a message for the first time. It assumes you have the library added to a Kotlin project. If you have not added the library yet, follow the [Getting Started](../how-to/get-started.md) guide first.

## What we will do

We will encrypt a plaintext message with ChaCha20-Poly1305. Then we will decrypt it back. You will see the full round trip. The output is visible at each step.

For background on why the API is designed this way, see [Architecture](../explanation/architecture.md) and [ADR-0005](../adr/0005-api-surface.md).

## Step 1: Generate a key

We need a 32-byte symmetric key. We generate random bytes for it.

```kotlin
val keyBytes = ByteArray(32) { 0x42 } // 32 bytes of 0x42 (demo only)
```

We wrap it in a `SecretKey` handle. The handle zeroes its bytes when we close it.

```kotlin
val key = SecretKey(keyBytes)
```

## Step 2: Encrypt a message

We call `Crypto.chacha20Poly1305Encrypt`. The library generates a fresh nonce for us. We never supply one.

```kotlin
val message = "Hello, encrypted world!".encodeToByteArray()

val result = Crypto.chacha20Poly1305Encrypt(key, message)
val ciphertext = result.getOrThrow()

println(ciphertext.joinToString("") { "%02x".format(it) })
```

The ciphertext has this layout:

```text
nonce (12 bytes) || encrypted message || tag (16 bytes)
```

The total length is `12 + message.length + 16`. For a 23-byte message, the ciphertext is 51 bytes.

## Step 3: Decrypt the ciphertext

We pass the same key and the full ciphertext blob. The library extracts the nonce, decrypts, and verifies the tag.

```kotlin
val decryptResult = Crypto.chacha20Poly1305Decrypt(key, ciphertext)
val plaintext = decryptResult.getOrThrow()

println(plaintext.decodeToString())
```

If the tag matches, `getOrThrow()` returns the plaintext. If the tag fails, `getOrThrow()` returns `null` (authentication failure, not an exception). If the input is malformed (wrong length), `getOrThrow()` throws.

## Step 4: Clean up the key

We close the key handle. This zeroes the backing byte array.

```kotlin
key.close()
```

Or we use `use` to scope it automatically:

```kotlin
SecretKey(keyBytes).use { key ->
    val encrypted = Crypto.chacha20Poly1305Encrypt(key, message).getOrThrow()
    val decrypted = Crypto.chacha20Poly1305Decrypt(key, encrypted).getOrThrow()
    println(decrypted.decodeToString())
}
// key is zeroed here — we never see the bytes again.
```

## Full listing

```kotlin
import ch.trancee.meshlink.crypto.Crypto
import ch.trancee.meshlink.crypto.SecretKey

fun main() {
    val keyBytes = ByteArray(32) { 0x42 }
    val message = "Hello, encrypted world!".encodeToByteArray()

    SecretKey(keyBytes).use { key ->
        val encrypted = Crypto.chacha20Poly1305Encrypt(key, message).getOrThrow()
        println("Encrypted: ${encrypted.joinToString("") { "%02x".format(it) }}")

        val decrypted = Crypto.chacha20Poly1305Decrypt(key, encrypted).getOrThrow()
        println("Decrypted: ${decrypted.decodeToString()}")
    }
}
```

We encrypted a message, then decrypted it back. The key was zeroed on exit.

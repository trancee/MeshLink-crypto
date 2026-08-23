/*
 * Interop harness: verifies that dispatch objects (SHA256, X25519, etc.)
 * produce identical output to their *PureK counterparts. When a native
 * provider backend is wired into an actual, these tests catch any divergence.
 *
 * Source set: commonTest — runs on JVM, Android, and iOS.  iOS execution
 * is disabled by build.gradle.kts; tests still compile.
 * Spec: issue 11 "Native fallback dispatch (+ interop harness)" — native
 * result == pure-K result on each target.
 */
package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class InteropHarnessTest {

  @Test
  fun sha256_matchesPureK() {
    val input = "abc".encodeToByteArray()
    assertContentEquals(SHA256PureK.digest(input), SHA256.digest(input))
  }

  @Test
  fun sha512_matchesPureK() {
    val input = "abc".encodeToByteArray()
    assertContentEquals(SHA512PureK.digest(input), SHA512.digest(input))
  }

  @Test
  fun hmacSha256_digest_matchesPureK() {
    val key = "key".encodeToByteArray()
    val msg = "The quick brown fox jumps over the lazy dog".encodeToByteArray()
    assertContentEquals(HMAC_SHA256PureK.digest(key, msg), HMAC_SHA256.digest(key, msg))
  }

  @Test
  fun hmacSha256_verify_matchesPureK() {
    val key = "key".encodeToByteArray()
    val msg = "The quick brown fox".encodeToByteArray()
    val tag = HMAC_SHA256PureK.digest(key, msg)
    assertEquals(HMAC_SHA256PureK.verify(key, msg, tag), HMAC_SHA256.verify(key, msg, tag))
  }

  @Test
  fun hkdfSha256_matchesPureK() {
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt-value".encodeToByteArray()
    val info = "info-string".encodeToByteArray()
    val len = 32
    assertContentEquals(
        HKDF_SHA256PureK.digest(ikm, salt, info, len),
        HKDF_SHA256.digest(ikm, salt, info, len),
    )
    assertContentEquals(HKDF_SHA256PureK.extract(ikm, salt), HKDF_SHA256.extract(ikm, salt))
    val prk = HKDF_SHA256PureK.extract(ikm, salt)
    assertContentEquals(HKDF_SHA256PureK.expand(prk, info, len), HKDF_SHA256.expand(prk, info, len))
  }

  @Test
  fun x25519_matchesPureK() {
    val scalar = ByteArray(32) { (it + 1).toByte() }
    val u = ByteArray(32) { 0x02 }
    assertContentEquals(X25519PureK.compute(scalar, u), X25519.compute(scalar, u))
  }

  @Test
  fun ed25519_matchesPureK() {
    val secretKey = ByteArray(32) { (it + 1).toByte() }
    val message = "test message".encodeToByteArray()
    assertContentEquals(
        Ed25519PureK.publicKeyFromPrivate(secretKey),
        Ed25519.publicKeyFromPrivate(secretKey),
    )
    assertContentEquals(Ed25519PureK.sign(secretKey, message), Ed25519.sign(secretKey, message))
    val signature = Ed25519PureK.sign(secretKey, message)
    val publicKey = Ed25519PureK.publicKeyFromPrivate(secretKey)
    assertEquals(
        Ed25519PureK.verify(publicKey, message, signature),
        Ed25519.verify(publicKey, message, signature),
    )
  }

  @Test
  fun chacha20Poly1305_matchesPureK() {
    val key = ByteArray(32) { (it + 1).toByte() }
    val nonce = ByteArray(12) { 0x01 }
    val aad = byteArrayOf()
    val plaintext = "secret message".encodeToByteArray()

    // explicit-nonce path is deterministic — compare outputs
    assertContentEquals(
        ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad, plaintext),
        ChaCha20Poly1305.encryptWithNonce(key, nonce, aad, plaintext),
    )
    val ct = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad, plaintext)
    assertContentEquals(
        ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, aad, ct),
        ChaCha20Poly1305.decryptWithNonce(key, nonce, aad, ct),
    )

    // round-trip: encrypt with pure-K, decrypt with dispatch
    val ct2 = ChaCha20Poly1305PureK.encrypt(key, plaintext)
    val pt = ChaCha20Poly1305.decrypt(key, ct2)
    assertNotNull(pt)
    assertContentEquals(plaintext, pt)
  }

  @Test
  fun shake256_matchesPureK() {
    val input = "abc".encodeToByteArray()
    assertContentEquals(
        SHAKE256PureK.digest(input, 32),
        SHAKE256.digest(input, 32),
    )
    assertContentEquals(
        SHAKE256PureK.digest(input, 64),
        SHAKE256.digest(input, 64),
    )
  }
}

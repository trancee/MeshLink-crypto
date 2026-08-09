/*
 * Tests for pure-Kotlin ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
 *
 * Correctness oracle: RFC 8439 §2.3.2 (ChaCha20 block), §2.8 (AEAD KAT),
 * plus Wycheproof (256 valid + 60 ModifiedTag invalid vectors).
 */
package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

internal class ChaCha20Poly1305Test {

  // ------------------------------------------------------------------
  // RFC 8439 §2.3.2 — ChaCha20 keystream block (counter = 1)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `ChaCha20 block 1 keystream matches RFC 8439 Section 2p3p2`() {
    // Key = 000102...1f, nonce = 000000090000004a00000000, counter = 1
    val key = (0 until 32).map { it.toByte() }.toByteArray()
    val nonce = hex("000000090000004a00000000")
    val expectedBlock =
        hex(
            "10f1e7e4d13b5915500fdd1fa32071c4" +
                "c7d1f4c733c068030422aa9ac3d46c4e" +
                "d2826446079faa0914c2d705d98b02a2" +
                "b5129cd1de164eb9cbd083e8a2503c4e"
        )

    val block = ChaCha20.block(key, 1, nonce)
    assertContentEquals(expectedBlock, block, "keystream block must match RFC 8439 §2.3.2")
  }

  // ------------------------------------------------------------------
  // RFC 8439 §2.8 — AEAD encryption + decryption KAT (Wycheproof tcId 1)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `ChaCha20-Poly1305 RFC 8439 Section 2p8 KAT - encrypt and decrypt`() {
    // The well-known RFC 7539 / 8439 AEAD test vector (also Wycheproof tcId 1).
    val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    val nonce = hex("070000004041424344454647")
    val aad = hex("50515253c0c1c2c3c4c5c6c7")
    val plaintext =
        hex(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f6620" +
                "2739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e6520" +
                "74697020666f7220746865206675747572652c2073756e73637265656e20776f756c6420" +
                "62652069742e"
        )
    val expectedCt =
        hex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca" +
                "9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c98" +
                "03aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d2658" +
                "6cec64b6116"
        )
    val expectedTag = hex("1ae10b594f09e26a7e902ecbd0600691")

    // Encrypt with explicit nonce + AAD must produce the expected ciphertext || tag.
    val ctWithTag = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad, plaintext)
    assertContentEquals(
        expectedCt + expectedTag,
        ctWithTag,
        "RFC 8439 §2.8 ciphertext || tag must match",
    )

    // Decrypt must reproduce the original plaintext.
    val decrypted =
        ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, aad, expectedCt + expectedTag)
    assertContentEquals(plaintext, decrypted, "RFC 8439 §2.8 decrypt must match")

    // Public encrypt/decrypt round-trip with internal nonce.
    val sealed = ChaCha20Poly1305PureK.encrypt(key, plaintext)
    val recovered = ChaCha20Poly1305PureK.decrypt(key, sealed)
    assertContentEquals(plaintext, recovered, "public encrypt/decrypt round-trip")
  }

  // ------------------------------------------------------------------
  // Tamper detection (security boundary)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("security")
  @Test
  fun `ChaCha20-Poly1305 decrypt rejects flipped tag bit`() {
    val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    val nonce = hex("070000004041424344454647")
    val aad = hex("50515253c0c1c2c3c4c5c6c7")
    val plaintext = hex("4c616469657320616e642047656e746c656d656e")
    val ctWithTag = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad, plaintext)

    // Flip one bit in the tag (last byte).
    val tampered = ctWithTag.copyOf()
    tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte()
    assertNull(
        ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, aad, tampered),
        "flipped tag must return null",
    )
  }

  @Tag("positive")
  @Tag("security")
  @Test
  fun `ChaCha20-Poly1305 decrypt rejects flipped ciphertext bit`() {
    val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    val nonce = hex("070000004041424344454647")
    val plaintext = hex("4c616469657320616e642047656e746c656d656e")
    val ctWithTag = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, ByteArray(0), plaintext)

    // Flip one bit in the ciphertext (first encrypted byte).
    val tampered = ctWithTag.copyOf()
    tampered[0] = (tampered[0].toInt() xor 0x01).toByte()
    assertNull(
        ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, ByteArray(0), tampered),
        "flipped ciphertext bit must fail MAC verification",
    )
  }

  @Tag("positive")
  @Tag("security")
  @Test
  fun `ChaCha20-Poly1305 decrypt rejects wrong key`() {
    val key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    val wrongKey = hex("0000000000000000000000000000000000000000000000000000000000000000")
    val nonce = hex("070000004041424344454647")
    val plaintext = hex("4c616469657320")
    val ctWithTag = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, ByteArray(0), plaintext)

    assertNull(
        ChaCha20Poly1305PureK.decryptWithNonce(wrongKey, nonce, ByteArray(0), ctWithTag),
        "wrong key must fail MAC verification",
    )
  }

  // ------------------------------------------------------------------
  // Edge cases
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20-Poly1305 empty message round-trip`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    val ct = ChaCha20Poly1305PureK.encrypt(key, ByteArray(0))
    assertEquals(28, ct.size, "empty message → 12-byte nonce + 16-byte tag")
    val plaintext = ChaCha20Poly1305PureK.decrypt(key, ct)
    assertNotNull(plaintext, "empty-message decrypt must not return null")
    assertEquals(0, plaintext.size)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20-Poly1305 reject too-short ciphertext`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    // 12-byte nonce + less than 16-byte tag → too short.
    assertNull(
        ChaCha20Poly1305PureK.decrypt(key, ByteArray(27)),
        "too-short ciphertext must return null",
    )
    assertNull(
        ChaCha20Poly1305PureK.decrypt(key, ByteArray(0)),
        "empty ciphertext must return null",
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `ChaCha20-Poly1305 round-trip with random key at various sizes`() {
    val key = ByteArray(32) { (it * 17 + 3).toByte() }
    val messages =
        listOf(
            ByteArray(0),
            "abc".encodeToByteArray(),
            ByteArray(48) { 0x61 }, // < 1 block
            ByteArray(64) { 0x42 }, // exactly 1 block
            ByteArray(65) { 0x43 }, // 1 block + 1 byte
            ByteArray(128) { 0x44 }, // 2 blocks
            ByteArray(1024) { 0x45 }, // 16 blocks
        )
    repeat(8) { seed ->
      messages.forEach { msg ->
        val ct = ChaCha20Poly1305PureK.encrypt(key, msg)
        val pt = ChaCha20Poly1305PureK.decrypt(key, ct)
        assertNotNull(pt, "decrypt must succeed for seed=$seed msgLen=${msg.size}")
        assertContentEquals(msg, pt, "round-trip must preserve data (seed=$seed)")
      }
    }
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20-Poly1305 with non-empty AAD round-trip`() {
    val key = ByteArray(32) { (it * 13 + 1).toByte() }
    val nonce = ByteArray(12) { (it + 1).toByte() }
    val aad = "associated data for testing".encodeToByteArray()
    val plaintext = ByteArray(50) { (it + 10).toByte() }
    val ctWithTag = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad, plaintext)
    val recovered = ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, aad, ctWithTag)
    assertContentEquals(plaintext, recovered, "AAD round-trip must preserve plaintext")
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20-Poly1305 decrypt fails when AAD differs`() {
    val key = ByteArray(32) { (it * 13 + 1).toByte() }
    val nonce = ByteArray(12) { (it + 1).toByte() }
    val aad1 = "associated data for testing".encodeToByteArray()
    val aad2 = "tampered associated data!!".encodeToByteArray()
    val plaintext = ByteArray(50) { (it + 10).toByte() }
    val ctWithTag = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad1, plaintext)
    assertNull(
        ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, aad2, ctWithTag),
        "mismatched AAD must fail authentication",
    )
  }

  // ------------------------------------------------------------------
  // Input-length validation
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20-Poly1305 rejects wrong key length`() {
    val key31 = ByteArray(31)
    val nonce = ByteArray(12) { (it + 1).toByte() }
    val msg = "hi".encodeToByteArray()
    val result = runCatching {
      ChaCha20Poly1305PureK.encryptWithNonce(key31, nonce, ByteArray(0), msg)
    }
    assertTrue(result.isFailure, "31-byte key must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20-Poly1305 rejects wrong nonce length`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    val nonce11 = ByteArray(11)
    val msg = "hi".encodeToByteArray()
    val result = runCatching {
      ChaCha20Poly1305PureK.encryptWithNonce(key, nonce11, ByteArray(0), msg)
    }
    assertTrue(result.isFailure, "11-byte nonce must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  // ------------------------------------------------------------------
  // Wycheproof vectors (correctness oracle, ADR-0003)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `ChaCha20-Poly1305 Wycheproof valid vectors - decrypt returns plaintext`() {
    val vectors = loadWycheproofChacha20Poly1305("/wycheproof/chacha20_poly1305_test.json")
    val valid = vectors.filter { it.result == "valid" && it.nonce.size == 12 }
    assertTrue(valid.isNotEmpty(), "Wycheproof resource must contain 12-byte-nonce valid vectors")
    assertEquals(256, valid.size, "must have 256 valid 96-bit-nonce vectors")

    valid.forEach { tc ->
      val ctWithTag = tc.ciphertext + tc.tag
      val plaintext = ChaCha20Poly1305PureK.decryptWithNonce(tc.key, tc.nonce, tc.aad, ctWithTag)
      assertContentEquals(
          tc.plaintext,
          plaintext,
          "tcId=${tc.tcId} comment=${tc.comment} flags=${tc.flags}",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Tag("security")
  @Test
  fun `ChaCha20-Poly1305 Wycheproof invalid vectors - decrypt returns null`() {
    val vectors = loadWycheproofChacha20Poly1305("/wycheproof/chacha20_poly1305_test.json")
    // Exclude InvalidNonceSize cases: our API mandates 12-byte nonces.
    val invalid = vectors.filter { it.result == "invalid" && it.nonce.size == 12 }
    assertTrue(
        invalid.isNotEmpty(),
        "Wycheproof resource must contain 12-byte-nonce invalid vectors",
    )

    invalid.forEach { tc ->
      val ctWithTag = tc.ciphertext + tc.tag
      val plaintext = ChaCha20Poly1305PureK.decryptWithNonce(tc.key, tc.nonce, tc.aad, ctWithTag)
      assertNull(
          plaintext,
          "tcId=${tc.tcId} comment=${tc.comment} flags=${tc.flags} must fail",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `ChaCha20-Poly1305 Wycheproof vector count`() {
    val vectors = loadWycheproofChacha20Poly1305("/wycheproof/chacha20_poly1305_test.json")
    assertEquals(325, vectors.size, "Wycheproof ChaCha20-Poly1305 must contain 325 test cases")
  }

  // ------------------------------------------------------------------
  // Internal primitive validation — require-failure and null-return paths
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20 block rejects wrong key length`() {
    val nonce = ByteArray(12) { (it + 1).toByte() }
    val result = runCatching { ChaCha20.block(ByteArray(31), 0, nonce) }
    assertTrue(result.isFailure, "31-byte key must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20 block rejects wrong nonce length`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    val result = runCatching { ChaCha20.block(key, 0, ByteArray(11)) }
    assertTrue(result.isFailure, "11-byte nonce must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20 streamXor rejects wrong key length`() {
    val nonce = ByteArray(12) { (it + 1).toByte() }
    val result = runCatching { ChaCha20.streamXor(ByteArray(31), nonce, 1, ByteArray(10)) }
    assertTrue(result.isFailure, "31-byte key must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20 streamXor rejects wrong nonce length`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    val result = runCatching { ChaCha20.streamXor(key, ByteArray(11), 1, ByteArray(10)) }
    assertTrue(result.isFailure, "11-byte nonce must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `Poly1305 mac rejects wrong key length`() {
    val result = runCatching { Poly1305.mac(ByteArray(31), ByteArray(10)) }
    assertTrue(result.isFailure, "31-byte key must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `Poly1305 mac handles non-16-byte data`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    val tag0 = Poly1305.mac(key, ByteArray(0))
    val tag1 = Poly1305.mac(key, ByteArray(1))
    val tag15 = Poly1305.mac(key, ByteArray(15))
    val tag16 = Poly1305.mac(key, ByteArray(16))
    val tag17 = Poly1305.mac(key, ByteArray(17))
    assertEquals(16, tag0.size)
    assertEquals(16, tag1.size)
    assertEquals(16, tag15.size)
    assertEquals(16, tag16.size)
    assertEquals(16, tag17.size)
    // Same input → same output (deterministic)
    assertContentEquals(tag1, Poly1305.mac(key, ByteArray(1)))
    assertContentEquals(tag16, Poly1305.mac(key, ByteArray(16)))
    // Different lengths → different tags (padding bit position differs)
    assertFalse(tag0.contentEquals(tag1), "length-0 and length-1 must differ")
    assertFalse(tag15.contentEquals(tag16), "length-15 and length-16 must differ")
    assertFalse(tag16.contentEquals(tag17), "length-16 and length-17 must differ")
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20Poly1305 encrypt rejects wrong key length`() {
    val result = runCatching { ChaCha20Poly1305PureK.encrypt(ByteArray(31), ByteArray(10)) }
    assertTrue(result.isFailure, "31-byte key must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20Poly1305 decrypt rejects wrong key length`() {
    val result = runCatching { ChaCha20Poly1305PureK.decrypt(ByteArray(31), ByteArray(28)) }
    assertTrue(result.isFailure, "31-byte key must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20Poly1305 decryptWithNonce returns null for too-short ciphertext`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    val nonce = ByteArray(12) { (it + 1).toByte() }
    assertNull(
        ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, ByteArray(0), ByteArray(15)),
        "ciphertextWithTag shorter than TAG_SIZE must return null",
    )
    assertNull(
        ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, ByteArray(0), ByteArray(0)),
        "empty ciphertextWithTag must return null",
    )
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20Poly1305 decryptWithNonce rejects wrong key length`() {
    val nonce = ByteArray(12) { (it + 1).toByte() }
    val result = runCatching {
      ChaCha20Poly1305PureK.decryptWithNonce(ByteArray(31), nonce, ByteArray(0), ByteArray(32))
    }
    assertTrue(result.isFailure, "31-byte key must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `ChaCha20Poly1305 decryptWithNonce rejects wrong nonce length`() {
    val key = ByteArray(32) { (it * 7).toByte() }
    val result = runCatching {
      ChaCha20Poly1305PureK.decryptWithNonce(key, ByteArray(11), ByteArray(0), ByteArray(32))
    }
    assertTrue(result.isFailure, "11-byte nonce must throw")
    assertTrue(result.exceptionOrNull() is IllegalArgumentException)
  }
}

/*
 * Tests for the public API facade (ADR-0005).
 *
 * Coverage:
 * - KeyHandle close() wipes secret bytes
 * - Hasher sha256/sha512 produce correct output (KAT + PureK interop)
 * - All facade methods route through dispatch objects (native-or-pure-K)
 * - AEAD nonce is internally generated (caller never sees it)
 */
package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

class CryptoFacadeTest {

  // ------------------------------------------------------------------
  // KeyHandle close() wipes secret bytes
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `SecretKey close wipes backing bytes`() {
    val handle = SecretKey(ByteArray(32) { 0x42.toByte() })
    val before = handle.bytes
    assertContentEquals(ByteArray(32) { 0x42.toByte() }, before)
    handle.close()
    assertTrue(handle.bytes.all { it == 0.toByte() })
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `PrivateKey close wipes backing bytes`() {
    val handle = PrivateKey(ByteArray(32) { 0xAB.toByte() })
    handle.close()
    assertTrue(handle.bytes.all { it == 0.toByte() })
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `PublicKey close wipes backing bytes`() {
    val handle = PublicKey(ByteArray(32) { 0xCD.toByte() })
    handle.close()
    assertTrue(handle.bytes.all { it == 0.toByte() })
  }

  // ------------------------------------------------------------------
  // Hasher sha256 — known-answer test (FIPS 180-4)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  @Tag("kats")
  fun `Hasher sha256 ABC matches FIPS 180-4`() {
    val result = Hasher.sha256("abc".encodeToByteArray())
    assertTrue(result.isSuccess, "sha256 must not throw")
    assertContentEquals(
        hex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"),
        result.getOrThrow(),
    )
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher sha256 matches PureK interop`() {
    val input = "The quick brown fox jumps over the lazy dog".encodeToByteArray()
    val facade = Hasher.sha256(input).getOrThrow()
    assertContentEquals(SHA256PureK.digest(input), facade)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher sha512 matches PureK interop`() {
    val input = "The quick brown fox jumps over the lazy dog".encodeToByteArray()
    val facade = Hasher.sha512(input).getOrThrow()
    assertContentEquals(SHA512PureK.digest(input), facade)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher sha256 returns 32-byte digest`() {
    assertEquals(32, Hasher.sha256("abc".encodeToByteArray()).getOrThrow().size)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher sha512 returns 64-byte digest`() {
    assertEquals(64, Hasher.sha512("abc".encodeToByteArray()).getOrThrow().size)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher shake256 matches PureK interop`() {
    val input = "The quick brown fox jumps over the lazy dog".encodeToByteArray()
    val facade = Hasher.shake256(input, 64).getOrThrow()
    assertContentEquals(SHAKE256PureK.digest(input, 64), facade)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher shake256 returns requested output length`() {
    val input = "abc".encodeToByteArray()
    assertEquals(32, Hasher.shake256(input, 32).getOrThrow().size)
    assertEquals(137, Hasher.shake256(input, 137).getOrThrow().size)
    assertEquals(1000, Hasher.shake256(input, 1000).getOrThrow().size)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher shake128 matches PureK interop`() {
    val input = "The quick brown fox jumps over the lazy dog".encodeToByteArray()
    val facade = Hasher.shake128(input, 64).getOrThrow()
    assertContentEquals(SHAKE128PureK.digest(input, 64), facade)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Hasher shake128 returns requested output length`() {
    val input = "abc".encodeToByteArray()
    assertEquals(32, Hasher.shake128(input, 32).getOrThrow().size)
    assertEquals(169, Hasher.shake128(input, 169).getOrThrow().size)
    assertEquals(1000, Hasher.shake128(input, 1000).getOrThrow().size)
  }

  // ------------------------------------------------------------------
  // Authenticator (HMAC-SHA256)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Authenticator hmacSha256 round-trips with verify`() {
    val keyBytes = ByteArray(32) { (it + 1).toByte() }
    val message = "authenticated message".encodeToByteArray()
    val tag = Authenticator.hmacSha256(SecretKey(keyBytes.copyOf()), message).getOrThrow()
    assertTrue(
        Authenticator.verify(SecretKey(keyBytes.copyOf()), message, tag).getOrThrow(),
    )
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Authenticator verify rejects wrong tag`() {
    val key = SecretKey(ByteArray(32) { 0x01 })
    val message = "data".encodeToByteArray()
    val wrongTag = ByteArray(32) { 0xFF.toByte() }
    assertFalse(Authenticator.verify(key, message, wrongTag).getOrThrow())
  }

  // ------------------------------------------------------------------
  // Kdf (HKDF-SHA256)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Kdf hkdfSha256 matches PureK interop`() {
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt-value".encodeToByteArray()
    val info = "info-string".encodeToByteArray()
    assertContentEquals(
        HKDF_SHA256PureK.digest(ikm, salt, info, 32),
        Kdf.hkdfSha256(ikm, salt, info, 32).getOrThrow(),
    )
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Kdf extract matches PureK interop`() {
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt-value".encodeToByteArray()
    assertContentEquals(
        HKDF_SHA256PureK.extract(ikm, salt),
        Kdf.extract(ikm, salt).getOrThrow(),
    )
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Kdf expand matches PureK interop`() {
    val ikm = "ikm-value".encodeToByteArray()
    val salt = "salt-value".encodeToByteArray()
    val info = "info-string".encodeToByteArray()
    val prk = HKDF_SHA256PureK.extract(ikm, salt)
    assertContentEquals(
        HKDF_SHA256PureK.expand(prk, info, 48),
        Kdf.expand(prk, info, 48).getOrThrow(),
    )
  }

  // ------------------------------------------------------------------
  // KeyExchange (X25519)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  @Tag("kats")
  fun `KeyExchange x25519 Alice-Bob matches RFC 7748 Section 6p1`() {
    val aliceSecret = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    val bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    val expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assertContentEquals(
        expected,
        KeyExchange.x25519(PrivateKey(aliceSecret), PublicKey(bobPublic)).getOrThrow(),
    )
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `KeyExchange x25519 matches PureK interop`() {
    val scalar = ByteArray(32) { (it + 1).toByte() }
    val u = ByteArray(32) { 0x02 }
    assertContentEquals(
        X25519PureK.compute(scalar, u),
        KeyExchange.x25519(PrivateKey(scalar.copyOf()), PublicKey(u.copyOf())).getOrThrow(),
    )
  }

  // ------------------------------------------------------------------
  // Signer (Ed25519)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  @Tag("kats")
  fun `Signer ed25519 sign matches RFC 8032 Section 7p1 TEST 1`() {
    val secretKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    val message = ByteArray(0)
    val signature =
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
    assertContentEquals(
        signature,
        Signer.ed25519Sign(PrivateKey(secretKey), message).getOrThrow(),
    )
    assertTrue(
        Signer.ed25519Verify(PublicKey(publicKey), message, signature).getOrThrow(),
    )
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Signer ed25519 verify rejects invalid signature`() {
    val secretKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val publicKey = Ed25519PureK.publicKeyFromPrivate(secretKey)
    val message = "message".encodeToByteArray()
    val wrongSig = ByteArray(64) { 0xFF.toByte() }
    assertFalse(
        Signer.ed25519Verify(PublicKey(publicKey), message, wrongSig).getOrThrow(),
    )
  }

  // ------------------------------------------------------------------
  // Aead (ChaCha20-Poly1305)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Aead chacha20Poly1305 encrypt then decrypt round-trips`() {
    val keyBytes = ByteArray(32) { (it + 1).toByte() }
    val plaintext = "secret message".encodeToByteArray()
    val ciphertext =
        Aead.chacha20Poly1305Encrypt(SecretKey(keyBytes.copyOf()), plaintext).getOrThrow()
    // Output layout: nonce(12) || ciphertext || tag(16)
    assertEquals(12 + plaintext.size + 16, ciphertext.size)
    val decrypted =
        Aead.chacha20Poly1305Decrypt(SecretKey(keyBytes.copyOf()), ciphertext).getOrThrow()
    assertNotNull(decrypted)
    assertContentEquals(plaintext, decrypted)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Aead chacha20Poly1305 decrypt returns null on tampered ciphertext`() {
    val keyBytes = ByteArray(32) { (it + 1).toByte() }
    val plaintext = "secret message".encodeToByteArray()
    var ct = Aead.chacha20Poly1305Encrypt(SecretKey(keyBytes.copyOf()), plaintext).getOrThrow()
    // Flip a byte to break authentication
    ct = ct.copyOf()
    ct[12] = (ct[12].toInt() xor 0x01).toByte()
    val decrypted = Aead.chacha20Poly1305Decrypt(SecretKey(keyBytes.copyOf()), ct).getOrThrow()
    assertNull(decrypted)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Aead chacha20Poly1305 generates non-zero internal nonce`() {
    val key = SecretKey(ByteArray(32) { (it + 1).toByte() })
    val plaintext = "test".encodeToByteArray()
    val ct = Aead.chacha20Poly1305Encrypt(key, plaintext).getOrThrow()
    // Nonce is the first 12 bytes — must be non-zero (CSPRNG)
    val nonce = ct.copyOfRange(0, 12)
    assertTrue(nonce.any { it != 0.toByte() }, "nonce must not be all-zero")
    // Decrypt with the nonce prepended in the ciphertext
    val decrypted = Aead.chacha20Poly1305Decrypt(key, ct).getOrThrow()
    assertNotNull(decrypted)
    assertContentEquals(plaintext, decrypted)
  }

  // ------------------------------------------------------------------
  // Wycheproof vectors — facade dispatch (ADR-0003 + ADR-0005)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  fun `Kdf hkdfSha256 Wycheproof valid vectors - facade matches OKM`() {
    // Arrange
    val vectors = loadWycheproofHkdf("/wycheproof/hkdf_sha256_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof HKDF must contain valid vectors")

    // Act + Assert
    valid.forEach { tc ->
      val okm = Kdf.hkdfSha256(tc.ikm, tc.salt, tc.info, tc.outputLength).getOrThrow()
      assertContentEquals(
          tc.okm,
          okm,
          "tcId=${tc.tcId} ikmLen=${tc.ikm.size} okmLen=${tc.okm.size}",
      )
    }
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  fun `Authenticator hmacSha256 Wycheproof valid vectors - facade matches tag`() {
    // Arrange
    val vectors = loadWycheproof("/wycheproof/hmac_sha256_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof HMAC must contain valid vectors")

    // Act + Assert
    valid.forEach { tc ->
      val tag = Authenticator.hmacSha256(SecretKey(tc.key.copyOf()), tc.msg).getOrThrow()
      // Full 32-byte tags compare directly; truncated tags compare prefix.
      assertContentEquals(
          tc.tag,
          tag.copyOfRange(0, tc.tag.size),
          "tcId=${tc.tcId} keyLen=${tc.key.size} msgLen=${tc.msg.size} tagLen=${tc.tag.size}",
      )
    }
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  fun `KeyExchange x25519 Wycheproof valid vectors - facade matches shared secret`() {
    // Arrange
    val vectors = loadWycheproofX25519("/wycheproof/x25519_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof X25519 must contain valid vectors")

    // Act + Assert
    valid.forEach { tc ->
      val shared =
          KeyExchange.x25519(PrivateKey(tc.private.copyOf()), PublicKey(tc.public.copyOf()))
              .getOrThrow()
      assertContentEquals(
          tc.shared,
          shared,
          "tcId=${tc.tcId} comment=${tc.comment}",
      )
    }
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  fun `Signer ed25519 Wycheproof valid vectors - facade verifies signatures`() {
    // Arrange
    val vectors = loadWycheproofEd25519("/wycheproof/ed25519_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof Ed25519 must contain valid vectors")

    // Act + Assert
    valid.forEach { tc ->
      val accepted =
          Signer.ed25519Verify(PublicKey(tc.publicKey.copyOf()), tc.msg, tc.sig).getOrThrow()
      assertTrue(accepted, "tcId=${tc.tcId} must verify")
    }
  }

  // ------------------------------------------------------------------
  // Edge cases — boundaries, empty input, max output
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("edge-case")
  fun `Hasher sha256 empty input matches FIPS 180-4`() {
    // Arrange
    val input = ByteArray(0)

    // Act
    val digest = Hasher.sha256(input).getOrThrow()

    // Assert
    assertContentEquals(
        hex("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
        digest,
    )
  }

  @Test
  @Tag("positive")
  @Tag("edge-case")
  fun `Authenticator hmacSha256 empty key and message - computed known answer`() {
    // Arrange
    val key = SecretKey(ByteArray(0))
    val message = ByteArray(0)

    // Act
    val tag = Authenticator.hmacSha256(key, message).getOrThrow()

    // Assert
    assertContentEquals(
        hex("B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD"),
        tag,
    )
  }

  @Test
  @Tag("positive")
  @Tag("edge-case")
  fun `Kdf hkdfSha256 zero output length returns empty OKM`() {
    // Arrange
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt-value".encodeToByteArray()
    val info = "info-string".encodeToByteArray()

    // Act
    val okm = Kdf.hkdfSha256(ikm, salt, info, 0).getOrThrow()

    // Assert
    assertEquals(0, okm.size)
  }

  @Test
  @Tag("positive")
  @Tag("edge-case")
  fun `Kdf hkdfSha256 max output length 8160 bytes succeeds`() {
    // Arrange — 255 * 32 = 8160 per RFC 5869 §2.3
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt-value".encodeToByteArray()
    val info = "info-string".encodeToByteArray()
    val maxLen = 255 * 32

    // Act
    val okm = Kdf.hkdfSha256(ikm, salt, info, maxLen).getOrThrow()

    // Assert
    assertEquals(maxLen, okm.size)
    assertContentEquals(
        HKDF_SHA256PureK.digest(ikm, salt, info, maxLen),
        okm,
    )
  }

  @Test
  @Tag("edge-case")
  @Tag("negative")
  fun `Kdf hkdfSha256 exceeds max output length throws IllegalArgumentException`() {
    // Arrange — 8161 > 8160 (255 * 32) violates RFC 5869 §2.3
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt-value".encodeToByteArray()
    val info = "info-string".encodeToByteArray()

    // Act + Assert
    assertFailsWith<IllegalArgumentException> {
      Kdf.hkdfSha256(ikm, salt, info, 8161).getOrThrow()
    }
  }

  @Test
  @Tag("edge-case")
  @Tag("negative")
  fun `Kdf expand negative output length throws IllegalArgumentException`() {
    // Arrange
    val prk = ByteArray(32) { 0x01 }
    val info = "info".encodeToByteArray()

    // Act + Assert
    assertFailsWith<IllegalArgumentException> {
      Kdf.expand(prk, info, -1).getOrThrow()
    }
  }

  @Test
  @Tag("positive")
  @Tag("edge-case")
  fun `Aead chacha20Poly1305 decrypt with too-short ciphertext returns null`() {
    // Arrange — minimum valid output is nonce(12) + tag(16) = 28 bytes
    val key = SecretKey(ByteArray(32) { (it + 1).toByte() })
    val tooShort = ByteArray(20) { 0x00 }

    // Act
    val result = Aead.chacha20Poly1305Decrypt(key, tooShort)

    // Assert — truncated ciphertext is treated as auth failure (null), not a throw
    assertTrue(result.isSuccess)
    assertNull(result.getOrThrow())
  }

  @Test
  @Tag("edge-case")
  @Tag("negative")
  fun `Aead chacha20Poly1305 decrypt with wrong-size key fails`() {
    // Arrange — key must be 32 bytes; 16-byte key triggers require() failure
    val key = SecretKey(ByteArray(16) { 0x01 })
    val ciphertext = ByteArray(28) { 0x00 }

    // Act
    val result = Aead.chacha20Poly1305Decrypt(key, ciphertext)

    // Assert — malformed key input throws, wrapped as Result.failure
    assertTrue(result.isFailure)
  }

  // ------------------------------------------------------------------
  // Unified Crypto facade delegation tests (Candidate #5)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade sha256 delegates to Hasher`() {
    val input = "abc".encodeToByteArray()
    val expected = Hasher.sha256(input).getOrThrow()
    val actual = Crypto.sha256(input).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade sha512 delegates to Hasher`() {
    val input = "abc".encodeToByteArray()
    val expected = Hasher.sha512(input).getOrThrow()
    val actual = Crypto.sha512(input).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade shake256 delegates to Hasher`() {
    val input = "abc".encodeToByteArray()
    val expected = Hasher.shake256(input, 64).getOrThrow()
    val actual = Crypto.shake256(input, 64).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade shake128 delegates to Hasher`() {
    val input = "abc".encodeToByteArray()
    val expected = Hasher.shake128(input, 64).getOrThrow()
    val actual = Crypto.shake128(input, 64).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade hmacSha256 delegates to Authenticator`() {
    val key = SecretKey(ByteArray(32) { (it + 1).toByte() })
    val message = "test-message".encodeToByteArray()
    val expected = Authenticator.hmacSha256(key, message).getOrThrow()
    val actual = Crypto.hmacSha256(key, message).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade verifyHmacSha256 delegates to Authenticator`() {
    val key = SecretKey(ByteArray(32) { (it + 1).toByte() })
    val message = "test-message".encodeToByteArray()
    val tag = Authenticator.hmacSha256(key, message).getOrThrow()
    assertTrue(Crypto.verifyHmacSha256(key, message, tag).getOrThrow())
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade hkdfSha256 delegates to Kdf`() {
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt".encodeToByteArray()
    val info = "info".encodeToByteArray()
    val expected = Kdf.hkdfSha256(ikm, salt, info, 64).getOrThrow()
    val actual = Crypto.hkdfSha256(ikm, salt, info, 64).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade extract delegates to Kdf`() {
    val ikm = "input-key-material".encodeToByteArray()
    val salt = "salt".encodeToByteArray()
    val expected = Kdf.extract(ikm, salt).getOrThrow()
    val actual = Crypto.extract(ikm, salt).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade expand delegates to Kdf`() {
    val prk = ByteArray(32) { 0x01 }
    val info = "info".encodeToByteArray()
    val expected = Kdf.expand(prk, info, 64).getOrThrow()
    val actual = Crypto.expand(prk, info, 64).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade x25519 delegates to KeyExchange`() {
    val scalar = ByteArray(32) { 0x01 }
    val u = ByteArray(32) { 0x02 }
    val expected = KeyExchange.x25519(PrivateKey(scalar), PublicKey(u)).getOrThrow()
    val actual = Crypto.x25519(PrivateKey(scalar), PublicKey(u)).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade ed25519Sign delegates to Signer`() {
    val secretKey = ByteArray(32) { 0x01 }
    val message = "test-message".encodeToByteArray()
    val expected = Signer.ed25519Sign(PrivateKey(secretKey), message).getOrThrow()
    val actual = Crypto.ed25519Sign(PrivateKey(secretKey), message).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade ed25519Verify delegates to Signer`() {
    val secretKey = ByteArray(32) { 0x01 }
    val publicKey = Ed25519PureK.publicKeyFromPrivate(secretKey)
    val message = "test-message".encodeToByteArray()
    val signature = Signer.ed25519Sign(PrivateKey(secretKey), message).getOrThrow()
    assertTrue(Crypto.ed25519Verify(PublicKey(publicKey), message, signature).getOrThrow())
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade chacha20Poly1305Encrypt delegates to Aead`() {
    val key = SecretKey(ByteArray(32) { (it + 1).toByte() })
    val message = "test-message".encodeToByteArray()
    val ciphertext = Crypto.chacha20Poly1305Encrypt(key, message).getOrThrow()
    val plaintext = Aead.chacha20Poly1305Decrypt(key, ciphertext).getOrThrow()
    assertContentEquals(message, plaintext)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade chacha20Poly1305Decrypt delegates to Aead`() {
    val key = SecretKey(ByteArray(32) { (it + 1).toByte() })
    val message = "test-message".encodeToByteArray()
    val ciphertext = Aead.chacha20Poly1305Encrypt(key, message).getOrThrow()
    val expected = Aead.chacha20Poly1305Decrypt(key, ciphertext).getOrThrow()
    val actual = Crypto.chacha20Poly1305Decrypt(key, ciphertext).getOrThrow()
    assertContentEquals(expected, actual)
  }

  // ------------------------------------------------------------------
  // Candidate #2: require() fail-fast tests (wrong key/nonce sizes)
  // ------------------------------------------------------------------

  @Test
  @Tag("edge-case")
  @Tag("negative")
  fun `Crypto chacha20Poly1305Encrypt with wrong-size key fails fast`() {
    // Arrange — key must be 32 bytes; 16-byte key triggers require() failure
    val key = SecretKey(ByteArray(16) { 0x01 })
    val message = "test".encodeToByteArray()

    // Act
    val result = Crypto.chacha20Poly1305Encrypt(key, message)

    // Assert — fail-fast: IllegalArgumentException wrapped as Result.failure
    assertTrue(result.isFailure)
    assertFailsWith<IllegalArgumentException> {
      result.getOrThrow()
    }
  }

  @Test
  @Tag("edge-case")
  @Tag("negative")
  fun `Crypto chacha20Poly1305Decrypt with wrong-size key fails fast`() {
    // Arrange — key must be 32 bytes; 16-byte key triggers require() failure
    val key = SecretKey(ByteArray(16) { 0x01 })
    val ciphertext = ByteArray(28) { 0x00 }

    // Act
    val result = Crypto.chacha20Poly1305Decrypt(key, ciphertext)

    // Assert — fail-fast: IllegalArgumentException wrapped as Result.failure
    assertTrue(result.isFailure)
    assertFailsWith<IllegalArgumentException> {
      result.getOrThrow()
    }
  }

  // ------------------------------------------------------------------
  // Public key derivation tests (RFC 7748 §6.1 + RFC 8032 §7.1)
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `KeyExchange deriveX25519PublicKey matches RFC 7748 Section 6p1 Alice public key`() {
    // Arrange — Alice's private scalar and expected public key (RFC 7748 §6.1)
    val aliceScalar = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    val alicePublicKey = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    // Act
    val result = KeyExchange.deriveX25519PublicKey(PrivateKey(aliceScalar))

    // Assert — scalar * basepoint(9) must equal Alice's public key
    assertContentEquals(alicePublicKey, result.getOrThrow())
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Signer ed25519PublicKeyFromPrivate matches RFC 8032 Section 7p1 TEST 1`() {
    // Arrange — RFC 8032 §7.1 TEST 1 secret key and expected public key
    val secretKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val expectedPublicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    // Act
    val result = Signer.ed25519PublicKeyFromPrivate(PrivateKey(secretKey))

    // Assert — the derived public key must match the RFC 8032 vector
    assertContentEquals(expectedPublicKey, result.getOrThrow())
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade deriveX25519PublicKey delegates to KeyExchange`() {
    val aliceScalar = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    val expected = KeyExchange.deriveX25519PublicKey(PrivateKey(aliceScalar)).getOrThrow()
    val actual = Crypto.deriveX25519PublicKey(PrivateKey(aliceScalar)).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto facade ed25519PublicKeyFromPrivate delegates to Signer`() {
    val secretKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val expected = Signer.ed25519PublicKeyFromPrivate(PrivateKey(secretKey)).getOrThrow()
    val actual = Crypto.ed25519PublicKeyFromPrivate(PrivateKey(secretKey)).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto randomBytes returns correct length and is non-deterministic`() {
    // Arrange + Act — generate two 32-byte random arrays
    val a = Crypto.randomBytes(32)
    val b = Crypto.randomBytes(32)

    // Assert — correct length, and (statistically) never identical
    assertEquals(32, a.size)
    assertEquals(32, b.size)
    assertFalse { a.contentEquals(b) }
  }

  @Test
  @Tag("edge-case")
  @Tag("negative")
  fun `Crypto deriveX25519PublicKey with wrong-size scalar fails fast`() {
    // Arrange — scalar must be 32 bytes; 16-byte input triggers require() failure
    val shortScalar = PrivateKey(ByteArray(16) { 0x01 })

    // Act
    val result = Crypto.deriveX25519PublicKey(shortScalar)

    // Assert — fail-fast: IllegalArgumentException wrapped as Result.failure
    assertTrue(result.isFailure)
    assertFailsWith<IllegalArgumentException> {
      result.getOrThrow()
    }
  }

  // ------------------------------------------------------------------
  // ML-KEM-512 (FIPS 203) facade delegation
  // ------------------------------------------------------------------

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto mlkem512KeyPair delegates to Kem`() {
    // Arrange — deterministic seed for reproducibility
    val seed = Crypto.randomBytes(64)

    // Act — both facades should produce identical keypairs
    val (pk1, sk1) = Crypto.mlkem512KeyPair(seed).getOrThrow()
    val (pk2, sk2) = Kem.mlkem512KeyPair(seed).getOrThrow()

    // Assert — identical output, correct sizes
    assertContentEquals(pk1, pk2)
    assertContentEquals(sk1, sk2)
    assertEquals(MLKEM512.PUBLIC_KEY_BYTES, pk1.size)
    assertEquals(MLKEM512.SECRET_KEY_BYTES, sk1.size)
  }

  @Test
  @Tag("positive")
  @Tag("critical-path")
  fun `Crypto mlkem512Encaps and mlkem512Decaps round-trip`() {
    // Arrange — generate keypair
    val seed = Crypto.randomBytes(64)
    val (pk, sk) = Crypto.mlkem512KeyPair(seed).getOrThrow()

    // Act — encapsulate via Crypto facade, decapsify via Crypto facade
    val (ct, ss1) = Crypto.mlkem512Encaps(pk).getOrThrow()
    val ss2 = Crypto.mlkem512Decaps(sk, ct).getOrThrow()

    // Assert — shared secrets match, correct sizes
    assertContentEquals(ss1, ss2)
    assertEquals(MLKEM512.CIPHERTEXT_BYTES, ct.size)
    assertEquals(MLKEM512.SHARED_SECRET_BYTES, ss1.size)
  }
}

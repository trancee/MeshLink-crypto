package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

/**
 * Tests for pure-Kotlin Ed25519 (RFC 8032 §5.1).
 *
 * Correctness oracle: RFC 8032 §7.1 KAT vectors + Wycheproof Ed25519 vectors.
 */
internal class Ed25519Test {

  // ------------------------------------------------------------------
  // RFC 8032 §7.1 — Known-answer test vectors (sign + verify)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `Ed25519 RFC 8032 Section 7p1 TEST 1 - empty message`() {
    val secretKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    val message = ByteArray(0)
    val signature =
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )

    val derived = Ed25519PureK.publicKeyFromPrivate(secretKey)
    assertContentEquals(publicKey, derived, "public key must match RFC 8032 TEST 1")

    val signed = Ed25519PureK.sign(secretKey, message)
    assertContentEquals(signature, signed, "signature must match RFC 8032 TEST 1")

    assertTrue(Ed25519PureK.verify(publicKey, message, signature), "signature must verify")
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `Ed25519 RFC 8032 Section 7p1 TEST 2 - message 72`() {
    val secretKey = hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    val publicKey = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    val message = hex("72")
    val signature =
        hex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )

    assertContentEquals(
        publicKey,
        Ed25519PureK.publicKeyFromPrivate(secretKey),
        "public key must match",
    )
    assertContentEquals(signature, Ed25519PureK.sign(secretKey, message), "signature must match")
    assertTrue(Ed25519PureK.verify(publicKey, message, signature), "signature must verify")
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `Ed25519 RFC 8032 Section 7p1 TEST 3 - message af82`() {
    val secretKey = hex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
    val publicKey = hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
    val message = hex("af82")
    val signature =
        hex(
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        )

    assertContentEquals(
        publicKey,
        Ed25519PureK.publicKeyFromPrivate(secretKey),
        "public key must match",
    )
    assertContentEquals(signature, Ed25519PureK.sign(secretKey, message), "signature must match")
    assertTrue(Ed25519PureK.verify(publicKey, message, signature), "signature must verify")
  }

  // ------------------------------------------------------------------
  // Round-trip: sign then verify, with varied private keys
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `Ed25519 sign-then-verify round-trip with random secret keys`() {
    val messages =
        listOf(
            ByteArray(0),
            hex("af82"),
            ByteArray(256) { 0x01 },
            ByteArray(1024) { 0x42 },
            "Hello, World!".toByteArray(),
        )
    repeat(16) { seed ->
      val secretKey = ByteArray(32) { (seed * 17 + it * 31).toByte() }
      val publicKey = Ed25519PureK.publicKeyFromPrivate(secretKey)
      messages.forEach { msg ->
        val signature = Ed25519PureK.sign(secretKey, msg)
        assertTrue(
            Ed25519PureK.verify(publicKey, msg, signature),
            "round-trip must verify (seed=$seed)",
        )
      }
    }
  }

  @Tag("positive")
  @Tag("security")
  @Test
  fun `Ed25519 verify rejects tampered message`() {
    val secretKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val publicKey = Ed25519PureK.publicKeyFromPrivate(secretKey)
    val signature = Ed25519PureK.sign(secretKey, ByteArray(0))

    // Flip a bit in the message (empty → single byte)
    assertFalse(
        Ed25519PureK.verify(publicKey, byteArrayOf(0x00), signature),
        "tampered message must fail",
    )
  }

  @Tag("positive")
  @Tag("security")
  @Test
  fun `Ed25519 verify rejects signature with flipped R bit`() {
    val secretKey = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    val publicKey = Ed25519PureK.publicKeyFromPrivate(secretKey)
    val signature = Ed25519PureK.sign(secretKey, ByteArray(0)).copyOf()
    signature[0] = (signature[0].toInt() xor 1).toByte() // flip one bit in R

    assertFalse(Ed25519PureK.verify(publicKey, ByteArray(0), signature), "tampered R must fail")
  }

  // ------------------------------------------------------------------
  // Input-length validation
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `Ed25519 public key of wrong length is rejected`() {
    val result = runCatching { Ed25519PureK.verify(ByteArray(31), ByteArray(0), ByteArray(64)) }
    assertTrue(result.isSuccess, "31-byte public key should return false, not throw")
    // verify returns false for wrong sizes (not an exception)
    assertFalse(Ed25519PureK.verify(ByteArray(31), ByteArray(0), ByteArray(64)))
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `Ed25519 signature of wrong length is rejected`() {
    val result = runCatching { Ed25519PureK.verify(ByteArray(32), ByteArray(0), ByteArray(63)) }
    assertTrue(result.isSuccess, "63-byte signature should return false, not throw")
    assertFalse(Ed25519PureK.verify(ByteArray(32), ByteArray(0), ByteArray(63)))
  }

  @Tag("positive")
  @Tag("security")
  @Test
  fun `Ed25519 verify rejects invalid public key encoding`() {
    // y = 1 (identity point) with sign bit 1 — x = 0, so this is an invalid encoding.
    val invalidPublicKey = hex("0100000000000000000000000000000000000000000000000000000000000080")
    val signature = ByteArray(64) // R = 0, S = 0 (canonical since 0 < group order L)
    assertFalse(
        Ed25519PureK.verify(invalidPublicKey, ByteArray(0), signature),
        "verify must reject invalid public key encoding",
    )
  }

  @Tag("positive")
  @Tag("security")
  @Test
  fun `Ed25519 verify with identity-point public key returns false`() {
    // y = 1, x = 0, sign bit 0 — a valid encoding of the identity point (0,1).
    val identityPublicKey = hex("0100000000000000000000000000000000000000000000000000000000000000")
    // Forged signature: R = identity point encoding, S = 0.
    // WITHOUT the identity-point check, [0]B + [h]*identity = identity + identity = identity = R,
    // so verification succeeds for any message. WITH the fix, verify must reject.
    val forgedSignature = identityPublicKey + ByteArray(32)
    assertFalse(
        Ed25519PureK.verify(identityPublicKey, ByteArray(0), forgedSignature),
        "identity point cannot verify any signature — forgery must be rejected (CVE-2023-38490)",
    )
  }

  // ------------------------------------------------------------------
  // Wycheproof Ed25519 vectors (correctness oracle, ADR-0003)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `Ed25519 Wycheproof valid vectors - verify returns true`() {
    val vectors = loadWycheproofEd25519("/wycheproof/ed25519_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof resource must contain valid vectors")

    valid.forEach { testCase ->
      assertTrue(
          Ed25519PureK.verify(testCase.publicKey, testCase.msg, testCase.sig),
          "tcId=${testCase.tcId} comment=${testCase.comment} result=${testCase.result} flags=${testCase.flags}",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Tag("security")
  @Test
  fun `Ed25519 Wycheproof invalid vectors - verify returns false`() {
    val vectors = loadWycheproofEd25519("/wycheproof/ed25519_test.json")
    val invalid = vectors.filter { it.result == "invalid" }
    assertTrue(invalid.isNotEmpty(), "Wycheproof resource must contain invalid vectors")

    invalid.forEach { testCase ->
      assertFalse(
          Ed25519PureK.verify(testCase.publicKey, testCase.msg, testCase.sig),
          "tcId=${testCase.tcId} comment=${testCase.comment} flags=${testCase.flags}",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `Ed25519 Wycheproof vector count`() {
    val vectors = loadWycheproofEd25519("/wycheproof/ed25519_test.json")
    assertEquals(150, vectors.size, "Wycheproof Ed25519 resource must contain 150 test cases")
  }
}

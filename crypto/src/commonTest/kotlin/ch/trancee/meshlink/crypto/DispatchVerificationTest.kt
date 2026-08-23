package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

/**
 * Dispatch verification (ADR-0002).
 *
 * Verifies that the public API (CryptoProvider → native → PureK) produces correct results by
 * checking against RFC known-answer vectors. The commonTest InteropHarnessTest already proves
 * dispatch == PureK; these tests prove the end-to-end path yields the correct cryptographic result.
 *
 * Each test emits a DISPATCH_TEST marker line to stdout, captured in JUnit XML <system-out>, for
 * ci-summary.py to render a per-test dispatch table.
 */
internal class DispatchVerificationTest {

  private fun hex(s: String): ByteArray {
    val clean = s.replace(" ", "")
    require(clean.length % 2 == 0) { "hex string must have even length" }
    return ByteArray(clean.length / 2) { i ->
      val hi = clean[i * 2].digitToInt(16)
      val lo = clean[i * 2 + 1].digitToInt(16)
      (hi shl 4 or lo).toByte()
    }
  }

  // ------------------------------------------------------------------
  // SHA-256 (RFC 6234 §B.1) — native (JCA / Darwin) on all platforms
  // ------------------------------------------------------------------
  @Test
  fun sha256_dispatchProducesCorrectDigest() {
    println("DISPATCH_TEST: SHA-256, path=native")
    val expected = hex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
    assertContentEquals(expected, SHA256.digest("abc".encodeToByteArray()))
  }

  // ------------------------------------------------------------------
  // SHA-512 (RFC 6234 §B.1) — native (JCA / Darwin) on all platforms
  // ------------------------------------------------------------------
  @Test
  fun sha512_dispatchProducesCorrectDigest() {
    println("DISPATCH_TEST: SHA-512, path=native")
    val expected =
        hex(
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A" +
                "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
        )
    assertContentEquals(expected, SHA512.digest("abc".encodeToByteArray()))
  }

  // ------------------------------------------------------------------
  // HMAC-SHA-256 (RFC 4231 §4.2.1) — native (JCA / Darwin) on all platforms
  // ------------------------------------------------------------------
  @Test
  fun hmacSha256_digestProducesCorrectTag() {
    println("DISPATCH_TEST: HMAC-SHA-256, path=native")
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    val expected = hex("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7")
    assertContentEquals(expected, HMAC_SHA256.digest(key, msg))
  }

  // ------------------------------------------------------------------
  // HKDF-SHA-256 (RFC 5869 Appendix A.1) — native (JCA HMAC) on all platforms
  // ------------------------------------------------------------------
  @Test
  fun hkdfSha256_dispatchProducesCorrectOutput() {
    println("DISPATCH_TEST: HKDF-SHA-256, path=native")
    val ikm = hex("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
    val salt = hex("000102030405060708090A0B0C")
    val info = hex("F0F1F2F3F4F5F6F7F8F9")
    val expected =
        hex(
            "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF" +
                "34007208D5B887185865"
        )
    assertContentEquals(expected, HKDF_SHA256.digest(ikm, salt, info, 42))
  }

  // ------------------------------------------------------------------
  // HMAC-SHA-256 verify (RFC 4231 §4.2.1) — correct tag verifies
  // ------------------------------------------------------------------
  @Test
  fun hmacSha256_verifyAcceptsCorrectTag() {
    println("DISPATCH_TEST: HMAC-SHA-256-verify, path=native")
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    val tag = hex("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7")
    assertTrue(HMAC_SHA256.verify(key, msg, tag))
  }

  // ------------------------------------------------------------------
  // X25519 (RFC 7748 §5.2) — native (JCA / Darwin) on JVM, PureK fallback on
  // physical Android < API 29
  // ------------------------------------------------------------------
  @Test
  fun x25519_dispatchProducesCorrectSharedSecret() {
    println("DISPATCH_TEST: X25519, path=native")
    val scalar = hex("A546E36BF0527C9D3B16154B82465EDD62144C0AC1FC5A18506A2244BA449AC4")
    val u = hex("E6DB6867583030DB3594C1A424B15F7C726624EC26B3353B10A903A6D0AB1C4C")
    val expected = hex("C3DA55379DE9C6908E94EA4DF28D084F32ECCF03491C71F754B4075577A28552")
    assertContentEquals(expected, X25519.compute(scalar, u))
  }

  // ------------------------------------------------------------------
  // Ed25519 sign (RFC 8032 §7.1 Test 1 — empty message) — native (JCA / Darwin)
  // on JVM, PureK fallback on physical Android < API 29
  // ------------------------------------------------------------------
  @Test
  fun ed25519_dispatchSignsCorrectly() {
    println("DISPATCH_TEST: Ed25519, path=native")
    val secretKey = hex("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60")
    val publicKey = hex("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A")
    val message = ByteArray(0)
    val expectedSignature =
        hex(
            "E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E06522490155" +
                "5FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B"
        )

    val derived = Ed25519.publicKeyFromPrivate(secretKey)
    assertContentEquals(publicKey, derived, "public key must match RFC 8032 TEST 1")
    assertContentEquals(expectedSignature, Ed25519.sign(secretKey, message))
    assertTrue(
        Ed25519.verify(publicKey, message, expectedSignature),
        "signature must verify",
    )
  }

  // ------------------------------------------------------------------
  // ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) — native (JCA) on JVM; PureK on
  // iOS (no CryptoKit C-API for ChaCha20-Poly1305)
  // ------------------------------------------------------------------
  @Test
  fun chacha20Poly1305_dispatchRoundTripsCorrectly() {
    println("DISPATCH_TEST: ChaCha20-Poly1305, path=native")
    val key = hex("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F")
    val message = "Ladies and Gentlemen of the class of '99".encodeToByteArray()

    val ciphertext = ChaCha20Poly1305.encrypt(key, message)
    val decrypted = ChaCha20Poly1305.decrypt(key, ciphertext)
    assertContentEquals(message, decrypted, "decrypt(encrypt(m)) must round-trip")
  }

  @Test
  fun chacha20Poly1305_dispatchRejectsTamperedCiphertext() {
    println("DISPATCH_TEST: ChaCha20-Poly1305-tamper, path=native")
    val key = hex("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F")
    val message = "tamper test".encodeToByteArray()

    val ciphertext = ChaCha20Poly1305.encrypt(key, message).toMutableList()
    // Flip one bit in the ciphertext — AEAD must reject.
    ciphertext[0] = (ciphertext[0].toInt() xor 0x01).toByte()
    assertTrue(
        ChaCha20Poly1305.decrypt(key, ciphertext.toByteArray()) == null,
        "tampered ciphertext must not decrypt",
    )
  }

  // ------------------------------------------------------------------
  // SHAKE256 (FIPS 202 §8.4) — no native path; PureK fallback on all platforms
  // ------------------------------------------------------------------
  @Test
  fun shake256_dispatchProducesCorrectDigest() {
    println("DISPATCH_TEST: SHAKE256, path=PureK")
    val input = "abc".encodeToByteArray()
    val expected =
        hex(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
                "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        )
    assertContentEquals(expected, SHAKE256.digest(input, 64))
  }
}

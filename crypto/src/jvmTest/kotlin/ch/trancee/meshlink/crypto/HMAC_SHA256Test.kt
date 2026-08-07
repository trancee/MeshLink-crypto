package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

/**
 * Tests for pure-Kotlin HMAC-SHA256 (RFC 2104 / RFC 4231, ADR-0003).
 *
 * Correctness oracle: RFC 4231 §4 known-answer vectors + Wycheproof HMAC-SHA256 vectors.
 */
internal class HMAC_SHA256Test {

  // ------------------------------------------------------------------
  // RFC 4231 §4.1.1 — known-answer test vectors (HMAC over SHA-256)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `HMAC SHA-256 RFC 4231 test 1 - key 0x0b twenty bytes, Hi There`() {
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    assertContentEquals(
        hex("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `HMAC SHA-256 RFC 4231 test 2 - key Jefe, what do ya want`() {
    val key = "Jefe".encodeToByteArray()
    val msg = "what do ya want for nothing?".encodeToByteArray()
    assertContentEquals(
        hex("5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `HMAC SHA-256 RFC 4231 test 3 - key 0x0b twenty bytes, 100 dd bytes`() {
    val key = ByteArray(20) { 0x0b }
    val msg = ByteArray(100) { 0xdd.toByte() }
    assertContentEquals(
        hex("0598ED470243A1A01FB354BDA6A05843DE5EC8514468B0229805C302E325155B"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `HMAC SHA-256 RFC 4231 test 4 - key 0x01-0x19, 50 cd bytes`() {
    val key = ByteArray(25) { (it + 1).toByte() } // 0x01..0x19
    val msg = ByteArray(50) { 0xcd.toByte() }
    assertContentEquals(
        hex("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  // ------------------------------------------------------------------
  // Wycheproof HMAC-SHA256 vectors (correctness oracle, ADR-0003)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `HMAC SHA-256 Wycheproof valid vectors - digest matches tag`() {
    val vectors = loadWycheproof("/wycheproof/hmac_sha256_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof resource must contain valid vectors")

    valid.forEach { testCase ->
      val computed = HMAC_SHA256.digest(testCase.key, testCase.msg)
      // Full 32-byte tags compare directly; 16-byte truncated tags compare prefix.
      val expectedLength = testCase.tag.size
      assertContentEquals(
          computed.copyOfRange(0, expectedLength),
          testCase.tag,
          "tcId=${testCase.tcId} keyLen=${testCase.key.size} msgLen=${testCase.msg.size} tagLen=${expectedLength}",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `HMAC SHA-256 Wycheproof full-tag valid vectors - verify returns true`() {
    val vectors = loadWycheproof("/wycheproof/hmac_sha256_test.json")
    val fullTagValid = vectors.filter { it.result == "valid" && it.tag.size == 32 }
    assertTrue(fullTagValid.isNotEmpty(), "must have full-tag valid vectors")

    fullTagValid.forEach { testCase ->
      assertTrue(
          HMAC_SHA256.verify(testCase.key, testCase.msg, testCase.tag),
          "tcId=${testCase.tcId} verify should accept correct full-length tag",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `HMAC SHA-256 Wycheproof invalid vectors - verify rejects modified tags`() {
    val vectors = loadWycheproof("/wycheproof/hmac_sha256_test.json")
    val invalid = vectors.filter { it.result == "invalid" }
    assertTrue(invalid.isNotEmpty(), "Wycheproof resource must contain invalid vectors")

    invalid.forEach { testCase ->
      assertFalse(
          HMAC_SHA256.verify(testCase.key, testCase.msg, testCase.tag),
          "tcId=${testCase.tcId} verify must reject modified/truncated tag",
      )
    }
  }

  // ------------------------------------------------------------------
  // Key-length boundary tests (exercises key normalization branch)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `HMAC SHA-256 empty key produces the correct digest`() {
    // Key shorter than block size → zero-padded, then XORed with ipad/opad.
    val key = ByteArray(0)
    val msg = ByteArray(0)
    assertContentEquals(
        hex("B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `HMAC SHA-256 key exactly block size is used directly without hashing`() {
    // Key length == 64 (block size): no hashing, key used as-is.
    val key = ByteArray(64) { 0x42 }
    val msg = "test".encodeToByteArray()
    assertContentEquals(
        hex("48335CCA4DCE044BF7E203EA2C0CB598C4070BFD03B329D95021E07495E68E6B"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `HMAC SHA-256 key longer than block size is hashed first`() {
    // Key length > 64 (block size): key is SHA-256(key) before use.
    val key = ByteArray(65) { 0x0b }
    val msg = "data".encodeToByteArray()
    assertContentEquals(
        hex("DE28139C725C5B6A71F7C9D48AFB8C6ED9F4AD09DF8B7994D0D7BA6723D6DD8F"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `HMAC SHA-256 key shorter than block size is zero-padded`() {
    val key = byteArrayOf(0x01, 0x02, 0x03)
    val msg = "msg".encodeToByteArray()
    assertContentEquals(
        hex("88EC2DA49AC6D7D71199DED8261B45B03567A627290B90A1A6F8BD929664B5F4"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  // ------------------------------------------------------------------
  // Message boundary tests
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `HMAC SHA-256 empty message produces correct digest`() {
    val key = ByteArray(20) { 0x0b }
    assertContentEquals(
        hex("999A901219F032CD497CADB5E6051E97B6A29AB297BD6AE722BD6062A2F59542"),
        HMAC_SHA256.digest(key, ByteArray(0)),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `HMAC SHA-256 message exactly block size`() {
    val key = ByteArray(20) { 0x0b }
    val msg = ByteArray(64) { 0x61 }
    assertContentEquals(
        hex("CCA2C75CDA09B876194A5E9076F0B37416042BD8E8D36F48ABEAD99753E62A64"),
        HMAC_SHA256.digest(key, msg),
    )
  }

  // ------------------------------------------------------------------
  // verify() — constant-time tag comparison
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HMAC SHA-256 verify accepts a correct tag`() {
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    val tag = HMAC_SHA256.digest(key, msg)
    assertTrue(HMAC_SHA256.verify(key, msg, tag), "correct tag must verify")
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HMAC SHA-256 verify rejects a single-bit-flipped tag`() {
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    val tag = HMAC_SHA256.digest(key, msg).apply { this[0] = (this[0].toInt() xor 0x01).toByte() }
    assertFalse(HMAC_SHA256.verify(key, msg, tag), "flipped tag must not verify")
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HMAC SHA-256 verify rejects a truncated tag`() {
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    val tag = HMAC_SHA256.digest(key, msg).copyOfRange(0, 16) // truncate to 16 bytes
    assertFalse(HMAC_SHA256.verify(key, msg, tag), "truncated tag must not verify")
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HMAC SHA-256 verify rejects an extended tag`() {
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    val tag = HMAC_SHA256.digest(key, msg) + byteArrayOf(0x00, 0x00, 0x00)
    assertFalse(HMAC_SHA256.verify(key, msg, tag), "extended tag must not verify")
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HMAC SHA-256 verify rejects empty tag`() {
    val key = ByteArray(20) { 0x0b }
    val msg = "Hi There".encodeToByteArray()
    assertFalse(
        HMAC_SHA256.verify(key, msg, ByteArray(0)),
        "empty tag must not verify",
    )
  }

  // ------------------------------------------------------------------
  // Timing harness integration (ADR-0003, seam 3)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HMAC SHA-256 timing harness records samples over varied inputs`() {
    val harness = TimingHarness()
    harness.measure(
        label = "HMAC-SHA-256",
        inputs =
            listOf(
                byteArrayOf(), // empty
                "Hi There".encodeToByteArray(),
                ByteArray(64) { 0x61 },
                ByteArray(128) { 0x62 },
            ),
        iterations = 100,
    ) { input ->
      val key = ByteArray(20) { 0x0b }
      HMAC_SHA256.digest(key, input)
    }
    assertEquals(4, harness.samples().size, "one sample per varied input")
    assertTrue(
        harness.samples().all { it.label == "HMAC-SHA-256" },
        "all samples carry the HMAC-SHA-256 label",
    )
  }
}

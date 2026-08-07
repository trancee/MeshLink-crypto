package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class SHA256Test {

  // ------------------------------------------------------------------
  // RFC 6234 Appendix B test vectors
  // ------------------------------------------------------------------

  @Test
  fun `SHA256 RFC 6234 test 1 - ABC`() {
    assertContentEquals(
        hex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"),
        SHA256.digest("abc".encodeToByteArray()),
    )
  }

  @Test
  fun `SHA256 RFC 6234 test 2 - abcdbcdecdef-trailing`() {
    val input =
        hex(
            "6162636462636465636465666465666765666768666768696768696A" +
                "68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
        )
    assertContentEquals(
        hex("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"),
        SHA256.digest(input),
    )
  }

  @Test
  fun `SHA256 RFC 6234 test 3 - one million a's`() {
    val input = ByteArray(1_000_000) { 0x61.toByte() }
    assertContentEquals(
        hex("CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"),
        SHA256.digest(input),
    )
  }

  @Test
  fun `SHA256 RFC 6234 test 4 - 64-byte block repeated 10 times`() {
    val half = "01234567012345670123456701234567".encodeToByteArray()
    val block = half + half // TEST4 = TEST4a + TEST4b (two identical 32-byte halves)
    val input = ByteArray(block.size * 10) { i -> block[i % block.size] }
    val digest = SHA256.digest(input)
    assertContentEquals(
        hex("594847328451BDFA85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5"),
        digest,
    )
  }

  @Test
  fun `SHA256 RFC 6234 test 6 - single byte 0x19`() {
    assertContentEquals(
        hex("68AA2E2EE5DFF96E3355E6C7EE373E3D6A4E17F75F9518D843709C0C9BC3E3D4"),
        SHA256.digest(byteArrayOf(0x19)),
    )
  }

  // ------------------------------------------------------------------
  // Edge cases (known-answer tests)
  // ------------------------------------------------------------------

  @Test
  fun `SHA256 empty message produces known empty-string digest`() {
    assertContentEquals(
        hex("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
        SHA256.digest(ByteArray(0)),
    )
  }

  @Test
  fun `SHA256 single-byte digest differs from empty`() {
    val empty = SHA256.digest(ByteArray(0))
    val one = SHA256.digest(byteArrayOf(0x42))
    assertFalse(empty.contentEquals(one), "digest must depend on content")
  }

  // ------------------------------------------------------------------
  // Block-boundary coverage (exercises every padding + branch path)
  // ------------------------------------------------------------------

  @Test
  fun `SHA256 boundary 55 bytes - padding fits in the first block`() {
    assertContentEquals(
        hex("9F4390F8D30C2DD92EC9F095B65E2B9AE9B0A925A5258E241C9F1E910F734318"),
        SHA256.digest(ByteArray(55) { 0x61 }),
    )
  }

  @Test
  fun `SHA256 boundary 56 bytes - padding spills to a second block`() {
    assertContentEquals(
        hex("B35439A4AC6F0948B6D6F9E3C6AF0F5F590CE20F1BDE7090EF7970686EC6738A"),
        SHA256.digest(ByteArray(56) { 0x61 }),
    )
  }

  @Test
  fun `SHA256 boundary 57 bytes - two bytes into the second block`() {
    assertContentEquals(
        hex("F13B2D724659EB3BF47F2DD6AF1ACCC87B81F09F59F2B75E5C0BED6589DFE8C6"),
        SHA256.digest(ByteArray(57) { 0x61 }),
    )
  }

  @Test
  fun `SHA256 boundary 63 bytes - last byte of the first block`() {
    assertContentEquals(
        hex("7D3E74A05D7DB15BCE4AD9EC0658EA98E3F06EEECF16B4C6FFF2DA457DDC2F34"),
        SHA256.digest(ByteArray(63) { 0x61 }),
    )
  }

  @Test
  fun `SHA256 boundary 64 bytes - exactly one full block`() {
    assertContentEquals(
        hex("FFE054FE7AE0CB6DC65C3AF9B61D5209F439851DB43D0BA5997337DF154668EB"),
        SHA256.digest(ByteArray(64) { 0x61 }),
    )
  }

  @Test
  fun `SHA256 boundary 128 bytes - exactly two full blocks`() {
    assertContentEquals(
        hex("6836CF13BAC400E9105071CD6AF47084DFACAD4E5E302C94BFED24E013AFB73E"),
        SHA256.digest(ByteArray(128) { 0x61 }),
    )
  }

  // ------------------------------------------------------------------
  // Incremental hasher tests (exercises SHA256Hasher buffering)
  // ------------------------------------------------------------------

  @Test
  fun `SHA256 incremental update matches one-shot digest`() {
    val data = ByteArray(200) { (it * 7).toByte() }
    val oneShot = SHA256.digest(data)

    val hasher = SHA256Hasher()
    // Feed in three uneven chunks to exercise buffering logic.
    hasher.update(data, 0, 50)
    hasher.update(data, 50, 100)
    hasher.update(data, 150, 50)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Test
  fun `SHA256 incremental update with defaults matches one-shot`() {
    val data = ByteArray(300) { (it * 13).toByte() }
    val oneShot = SHA256.digest(data)

    val hasher = SHA256Hasher()
    // Defaults: offset = 0, length = data.size
    hasher.update(data)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Test
  fun `SHA256 incremental update with partial offset matches one-shot`() {
    val data = ByteArray(200) { (it * 3).toByte() }
    val slice = data.copyOfRange(40, 150)
    val oneShot = SHA256.digest(slice)

    val hasher = SHA256Hasher()
    hasher.update(data, 40, 110)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Test
  fun `SHA256 digest over multi-update with exact-block boundaries`() {
    // 64 + 64 + 1 = 129 bytes: two full blocks + 1 byte buffered
    val a = ByteArray(64) { 0x61 }
    val b = ByteArray(64) { 0x62 }
    val c = byteArrayOf(0x63)
    val data = a + b + c
    val oneShot = SHA256.digest(data)

    val hasher = SHA256Hasher()
    hasher.update(a, 0, a.size)
    hasher.update(b, 0, b.size)
    hasher.update(c, 0, c.size)
    assertContentEquals(oneShot, hasher.digest())
  }

  // ------------------------------------------------------------------
  // Timing harness integration (ADR-0003, seam 3)
  // ------------------------------------------------------------------

  @Test
  fun `SHA256 timing harness records samples over varied input sizes`() {
    val harness = TimingHarness()
    harness.measure(
        label = "SHA-256",
        inputs =
            listOf(
                ByteArray(0),
                "abc".encodeToByteArray(),
                ByteArray(55) { 0x61 },
                ByteArray(56) { 0x61 },
                ByteArray(64) { 0x61 },
                ByteArray(128) { 0x61 },
                ByteArray(1_000_000) { 0x61 },
            ),
        iterations = 100,
    ) {
      SHA256.digest(it)
    }
    assertEquals(7, harness.samples().size, "one sample per varied input")
    assertTrue(
        harness.samples().all { it.label == "SHA-256" },
        "all samples carry the SHA-256 label",
    )
  }

  // ------------------------------------------------------------------
  // Test helper
  // ------------------------------------------------------------------

  private fun hex(s: String): ByteArray =
      ByteArray(s.length / 2) { i ->
        val hi = s[i * 2].digitToInt(16)
        val lo = s[i * 2 + 1].digitToInt(16)
        (hi shl 4 or lo).toByte()
      }
}

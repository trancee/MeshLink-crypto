package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class SHA512Test {

  // ------------------------------------------------------------------
  // RFC 6234 Appendix B test vectors
  // ------------------------------------------------------------------

  @Test
  fun `SHA512 RFC 6234 test 1 - ABC`() {
    assertContentEquals(
        hex(
            "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"
        ),
        SHA512.digest("abc".encodeToByteArray()),
    )
  }

  @Test
  fun `SHA512 RFC 6234 test 2 - one million a's`() {
    val input = ByteArray(1_000_000) { 0x61.toByte() }
    assertContentEquals(
        hex(
            "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B"
        ),
        SHA512.digest(input),
    )
  }

  // ------------------------------------------------------------------
  // Edge cases (known-answer tests)
  // ------------------------------------------------------------------

  @Test
  fun `SHA512 empty message produces known empty-string digest`() {
    assertContentEquals(
        hex(
            "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"
        ),
        SHA512.digest(ByteArray(0)),
    )
  }

  @Test
  fun `SHA512 single-byte digest differs from empty`() {
    val empty = SHA512.digest(ByteArray(0))
    val one = SHA512.digest(byteArrayOf(0x42))
    assertFalse(empty.contentEquals(one), "digest must depend on content")
  }

  // ------------------------------------------------------------------
  // Block-boundary coverage (exercises every padding + branch path)
  // SHA-512 block size = 128 bytes; padding boundary = 112 (128 - 16 length field)
  // ------------------------------------------------------------------

  @Test
  fun `SHA512 boundary 111 bytes - padding fits in the first block`() {
    assertContentEquals(
        hex(
            "FA9121C7B32B9E01733D034CFC78CBF67F926C7ED83E82200EF86818196921760B4BEFF48404DF811B953828274461673C68D04E297B0EB7B2B4D60FC6B566A2"
        ),
        SHA512.digest(ByteArray(111) { 0x61 }),
    )
  }

  @Test
  fun `SHA512 boundary 112 bytes - padding spills to a second block`() {
    assertContentEquals(
        hex(
            "C01D080EFD492776A1C43BD23DD99D0A2E626D481E16782E75D54C2503B5DC32BD05F0F1BA33E568B88FD2D970929B719ECBB152F58F130A407C8830604B70CA"
        ),
        SHA512.digest(ByteArray(112) { 0x61 }),
    )
  }

  @Test
  fun `SHA512 boundary 113 bytes - two bytes into the second block`() {
    assertContentEquals(
        hex(
            "55DDD8AC210A6E18BA1EE055AF84C966E0DBFF091C43580AE1BE703BDB85DA31ACF6948CF5BD90C55A20E5450F22FB89BD8D0085E39F85A86CC46ABBCA75E24D"
        ),
        SHA512.digest(ByteArray(113) { 0x61 }),
    )
  }

  @Test
  fun `SHA512 boundary 127 bytes - last byte of the first block`() {
    assertContentEquals(
        hex(
            "828613968B501DC00A97E08C73B118AA8876C26B8AAC93DF128502AB360F91BAB50A51E088769A5C1EFF4782ACE147DCE3642554199876374291F5D921629502"
        ),
        SHA512.digest(ByteArray(127) { 0x61 }),
    )
  }

  @Test
  fun `SHA512 boundary 128 bytes - exactly one full block`() {
    assertContentEquals(
        hex(
            "B73D1929AA615934E61A871596B3F3B33359F42B8175602E89F7E06E5F658A243667807ED300314B95CACDD579F3E33ABDFBE351909519A846D465C59582F321"
        ),
        SHA512.digest(ByteArray(128) { 0x61 }),
    )
  }

  @Test
  fun `SHA512 boundary 129 bytes - one byte into the second block`() {
    assertContentEquals(
        hex(
            "4F681E0BD53CDA4B5A2041CC8A06F2EABDE44FB16C951FBD5B87702F07AEAB611565B19C47FDE30587177EBB852E3971BBD8D3FD30DA18D71037DFBD98420429"
        ),
        SHA512.digest(ByteArray(129) { 0x61 }),
    )
  }

  // ------------------------------------------------------------------
  // Incremental hasher tests (exercises SHA512Hasher buffering)
  // ------------------------------------------------------------------

  @Test
  fun `SHA512 incremental update matches one-shot digest`() {
    val data = ByteArray(200) { (it * 7).toByte() }
    val oneShot = SHA512.digest(data)

    val hasher = SHA512Hasher()
    // Feed in three uneven chunks to exercise buffering logic.
    hasher.update(data, 0, 50)
    hasher.update(data, 50, 100)
    hasher.update(data, 150, 50)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Test
  fun `SHA512 incremental update with defaults matches one-shot`() {
    val data = ByteArray(300) { (it * 13).toByte() }
    val oneShot = SHA512.digest(data)

    val hasher = SHA512Hasher()
    // Defaults: offset = 0, length = data.size
    hasher.update(data)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Test
  fun `SHA512 incremental update with partial offset matches one-shot`() {
    val data = ByteArray(200) { (it * 3).toByte() }
    val slice = data.copyOfRange(40, 150)
    val oneShot = SHA512.digest(slice)

    val hasher = SHA512Hasher()
    hasher.update(data, 40, 110)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Test
  fun `SHA512 digest over multi-update with exact-block boundaries`() {
    // 128 + 128 + 1 = 257 bytes: two full blocks + 1 byte buffered
    val a = ByteArray(128) { 0x61 }
    val b = ByteArray(128) { 0x62 }
    val c = byteArrayOf(0x63)
    val data = a + b + c
    val oneShot = SHA512.digest(data)

    val hasher = SHA512Hasher()
    hasher.update(a, 0, a.size)
    hasher.update(b, 0, b.size)
    hasher.update(c, 0, c.size)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Test
  fun `SHA512 digest over multi-update with byte-at-a-time feeding`() {
    // Feed one byte at a time — exercises maximal buffering paths in processBlock.
    val data = ByteArray(130) { (it * 5).toByte() }
    val oneShot = SHA512.digest(data)

    val hasher = SHA512Hasher()
    for (i in data.indices) {
      hasher.update(data, i, 1)
    }
    assertContentEquals(oneShot, hasher.digest())
  }

  // ------------------------------------------------------------------
  // Timing harness integration (ADR-0003, seam 3)
  // ------------------------------------------------------------------

  @Test
  fun `SHA512 timing harness records samples over varied input sizes`() {
    val harness = TimingHarness()
    harness.measure(
        label = "SHA-512",
        inputs =
            listOf(
                ByteArray(0),
                "abc".encodeToByteArray(),
                ByteArray(111) { 0x61 },
                ByteArray(112) { 0x61 },
                ByteArray(128) { 0x61 },
                ByteArray(1_000_000) { 0x61 },
            ),
        iterations = 100,
    ) {
      SHA512.digest(it)
    }
    assertEquals(6, harness.samples().size, "one sample per varied input")
    assertTrue(
        harness.samples().all { it.label == "SHA-512" },
        "all samples carry the SHA-512 label",
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

package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

internal class SHAKE256Test {

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
  // FIPS 202 §D.5 SHAKE256 known-answer test vectors
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 empty message, 32-byte output`() {
    assertContentEquals(
        hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"),
        SHAKE256PureK.digest(ByteArray(0), 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 empty message, 64-byte output`() {
    assertContentEquals(
        hex(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        ),
        SHAKE256PureK.digest(ByteArray(0), 64),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 abc, 32-byte output`() {
    assertContentEquals(
        hex("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"),
        SHAKE256PureK.digest("abc".encodeToByteArray(), 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 abc, 64-byte output`() {
    assertContentEquals(
        hex(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
                "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        ),
        SHAKE256PureK.digest("abc".encodeToByteArray(), 64),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 byte 0x19, 32-byte output`() {
    assertContentEquals(
        hex("2f6b85952f8b6130486dafb6a7f2c76f23afd01768f13c4e3b8b390d17626e34"),
        SHAKE256PureK.digest(byteArrayOf(0x19.toByte()), 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 one million a's, 32-byte output`() {
    val input = ByteArray(1_000_000) { 0x61.toByte() }
    assertContentEquals(
        hex("3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a"),
        SHAKE256PureK.digest(input, 32),
    )
  }

  // ------------------------------------------------------------------
  // Extendable-output behavior (multi-block squeeze)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 abc, 200-byte output spans two squeeze blocks`() {
    assertContentEquals(
        hex(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
                "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4" +
                "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78d" +
                "bcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e" +
                "8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b33" +
                "a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe119"
        ),
        SHAKE256PureK.digest("abc".encodeToByteArray(), 200),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 abc, 136-byte output exactly one squeeze block`() {
    assertContentEquals(
        hex(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
                "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4" +
                "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78d" +
                "bcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e" +
                "8a2d7ec71a7cc29"
        ),
        SHAKE256PureK.digest("abc".encodeToByteArray(), 136),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 abc, 137-byte output crosses squeeze boundary`() {
    assertContentEquals(
        hex(
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739" +
                "d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4" +
                "1385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78d" +
                "bcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e" +
                "8a2d7ec71a7cc29cf"
        ),
        SHAKE256PureK.digest("abc".encodeToByteArray(), 137),
    )
  }

  // ------------------------------------------------------------------
  // Edge cases (known-answer tests)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 empty message, 1-byte output`() {
    assertContentEquals(
        hex("46"),
        SHAKE256PureK.digest(ByteArray(0), 1),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 empty message, 136-byte output exactly one squeeze block`() {
    assertContentEquals(
        hex(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be" +
                "141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853" +
                "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86" +
                "f3d122109e3b1fdd"
        ),
        SHAKE256PureK.digest(ByteArray(0), 136),
    )
  }

  // ------------------------------------------------------------------
  // Block-boundary coverage (exercises every absorb + padding path)
  // SHAKE256 rate = 136 bytes; padding boundary = 135 (rate - 1 for 0x80)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 boundary 135 bytes - padding fits in the first rate block`() {
    assertContentEquals(
        hex("55b991ece1e567b6e7c2c714444dd201cd51f4f3832d08e1d26bebc63e07a3d7"),
        SHAKE256PureK.digest(ByteArray(135) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 boundary 136 bytes - exactly one full rate block`() {
    assertContentEquals(
        hex("8fcc5a08f0a1f6827c9cf64ee8d16e0443106359ca6c8efd230759256f44996a"),
        SHAKE256PureK.digest(ByteArray(136) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 boundary 137 bytes - one byte into the second rate block`() {
    assertContentEquals(
        hex("a44e1a438dad6273d540be65ee26386c59588efb09139dc086385d2db0c25782"),
        SHAKE256PureK.digest(ByteArray(137) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 boundary 272 bytes - exactly two full rate blocks`() {
    assertContentEquals(
        hex("f0063200f64a4e66e186dcbd7e239bf2a72ca01077849d1dc89d02e7de5e2fa5"),
        SHAKE256PureK.digest(ByteArray(272) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `SHAKE256 boundary 273 bytes - one byte into the third rate block`() {
    assertContentEquals(
        hex("edfb81a13314cc592fb4c5ec5b11dc5c127494f9167c254641261ce14a8fa41e"),
        SHAKE256PureK.digest(ByteArray(273) { 0x61 }, 32),
    )
  }

  // ------------------------------------------------------------------
  // Multi-block absorb + multi-block squeeze
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 200-byte input with 200-byte output`() {
    val input = ByteArray(200) { 0x61.toByte() }
    assertContentEquals(
        hex(
            "e49647491c9d12d125a2f75826c96f6307d2fabebcbb9fb1616d76b09499380e" +
                "8bcf60f72750879140e73fb7453a979b69d25efa8de613462f108ce7f2f1d7c5" +
                "e444637301336604f42850beddef9434234ccc7d84196841069a7105379ca1e5" +
                "c6f79db0e8a7ef1f1ac2f55a76c5c355ddcd4cbac02037a93e18b0091df839a0" +
                "2a53df3e5af7a2811b70369652d13019887159d3fc9e8d36f0691168b3c7ec1d" +
                "88a1297c11c020ffa64166889651fcb8cc9e3170973701d8cf46faee26a9f8ba" +
                "e301ba265a442bff"
        ),
        SHAKE256PureK.digest(input, 200),
    )
  }

  // ------------------------------------------------------------------
  // Incremental hasher tests (exercises SHAKE256Hasher buffering)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 incremental update matches one-shot digest`() {
    val data = ByteArray(200) { (it * 7).toByte() }
    val oneShot = SHAKE256PureK.digest(data, 64)

    val hasher = SHAKE256Hasher()
    hasher.update(data, 0, 50)
    hasher.update(data, 50, 100)
    hasher.update(data, 150, 50)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 incremental update with defaults matches one-shot`() {
    val data = ByteArray(300) { (it * 13).toByte() }
    val oneShot = SHAKE256PureK.digest(data, 64)

    val hasher = SHAKE256Hasher()
    hasher.update(data)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 incremental update with partial offset matches one-shot`() {
    val data = ByteArray(200) { (it * 3).toByte() }
    val slice = data.copyOfRange(40, 150)
    val oneShot = SHAKE256PureK.digest(slice, 64)

    val hasher = SHAKE256Hasher()
    hasher.update(data, 40, 110)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 digest over multi-update with exact-block boundaries`() {
    // 136 + 136 + 1 = 273 bytes: two full rate blocks + 1 byte buffered
    val a = ByteArray(136) { 0x61 }
    val b = ByteArray(136) { 0x62 }
    val c = byteArrayOf(0x63)
    val data = a + b + c
    val oneShot = SHAKE256PureK.digest(data, 64)

    val hasher = SHAKE256Hasher()
    hasher.update(a, 0, a.size)
    hasher.update(b, 0, b.size)
    hasher.update(c, 0, c.size)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE256 digest over multi-update with byte-at-a-time feeding`() {
    // Feed one byte at a time — exercises maximal buffering paths.
    val data = ByteArray(300) { (it * 5).toByte() }
    val oneShot = SHAKE256PureK.digest(data, 64)

    val hasher = SHAKE256Hasher()
    data.forEachIndexed { i, _ -> hasher.update(data, i, 1) }
    assertContentEquals(oneShot, hasher.digest(64))
  }

  // ------------------------------------------------------------------
  // Timing harness integration (ADR-0003, seam 3)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `SHAKE256 timing harness records samples over varied input sizes`() {
    val harness = TimingHarness()
    harness.measure(
        label = "SHAKE256",
        inputs =
            listOf(
                ByteArray(0),
                "abc".encodeToByteArray(),
                ByteArray(135) { 0x61 },
                ByteArray(136) { 0x61 },
                ByteArray(272) { 0x61 },
                ByteArray(1_000_000) { 0x61 },
            ),
        iterations = 100,
    ) {
      SHAKE256PureK.digest(it, 32)
    }
    assertEquals(6, harness.samples().size, "one sample per varied input")
    assertTrue(
        harness.samples().all { it.label == "SHAKE256" },
        "all samples carry the SHAKE256 label",
    )
  }
}

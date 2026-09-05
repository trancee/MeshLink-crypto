package ch.trancee.meshlink.crypto

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Edge-case tests for [requireHex] and [FalconKatParser.parseRsp], following the
 * libacvp-json-kotlin skill methodology for strict field and hex validation.
 *
 * Tags: @Tag("positive"), @Tag("critical-path"), @Tag("known-answer"), @Tag("boundary")
 */
@Tag("positive")
@Tag("critical-path")
@Tag("known-answer")
@Tag("boundary")
internal class FalconKatLoaderTest {

  // ------------------------------------------------------------------
  // requireHex tests
  // ------------------------------------------------------------------

  @Test
  fun requireHex_decodesValidEvenLengthHex() {
    val bytes = requireHex("48656c6c6f", "test")
    assertEquals(5, bytes.size)
    assertEquals(0x48, bytes[0].toInt() and 0xFF)
  }

  @Test
  fun requireHex_acceptsUppercaseAndLowercase() {
    val upper = requireHex("DEADBEEF", "test")
    val lower = requireHex("deadbeef", "test")
    val mixed = requireHex("DeadBeef", "test")
    // All three should produce identical byte arrays
    assertTrue(upper.contentEquals(lower))
    assertTrue(upper.contentEquals(mixed))
  }

  @Test
  fun requireHex_rejectsEmptyWhenNotAllowed() {
    assertFailsWith<IllegalArgumentException> { requireHex("", "test") }
  }

  @Test
  fun requireHex_rejectsNull() {
    assertFailsWith<IllegalArgumentException> { requireHex(null, "test") }
  }

  @Test
  fun requireHex_allowsEmptyWhenAllowed() {
    val bytes = requireHex("", "test", expectedBytes = 0, allowEmpty = true)
    assertEquals(0, bytes.size)
  }

  @Test
  fun requireHex_rejectsOddLength() {
    assertFailsWith<IllegalArgumentException> { requireHex("ABC", "test") }
  }

  @Test
  fun requireHex_rejectsNonHexCharacters() {
    assertFailsWith<IllegalArgumentException> { requireHex("XYZ123", "test") }
  }

  @Test
  fun requireHex_rejectsWrongByteWidth() {
    // Too short
    assertFailsWith<IllegalArgumentException> {
      requireHex("0011", "test", expectedBytes = 8)
    }
    // Exact match — no error
    val ok = requireHex("0011223344556677", "test", expectedBytes = 8)
    assertEquals(8, ok.size)
    // Too long
    assertFailsWith<IllegalArgumentException> {
      requireHex("001122334455667788", "test", expectedBytes = 8)
    }
  }

  // ------------------------------------------------------------------
  // parseRsp tests
  // ------------------------------------------------------------------

  /** Builds a minimal valid .rsp vector. Override fields for edge cases. */
  private fun validKatRsp(
      count: String = "0",
      seed: String = "00".repeat(FALCON512_SEED_BYTES),
      mlen: String = "0",
      msg: String = "",
      pk: String = "00".repeat(FALCON512_PK_BYTES),
      sk: String = "00".repeat(FALCON512_SK_BYTES),
      smlen: String = "1",
      sm: String = "00",
  ): String =
      """
      |count = $count
      |seed = $seed
      |mlen = $mlen
      |msg = $msg
      |pk = $pk
      |sk = $sk
      |smlen = $smlen
      |sm = $sm
      """
          .trimMargin()

  @Test
  fun parseRsp_parsesSingleVector() {
    val rsp = validKatRsp()
    val vectors = FalconKatParser.parseRsp(rsp)
    assertEquals(1, vectors.size)

    val v = vectors[0]
    assertEquals(0L, v.count)
    assertEquals(FALCON512_SEED_BYTES, v.seed.size)
    assertEquals(FALCON512_PK_BYTES, v.pk.size)
    assertEquals(FALCON512_SK_BYTES, v.sk.size)
  }

  @Test
  fun parseRsp_parsesMultipleVectors() {
    val rsp = validKatRsp(count = "0") + "\n\n" + validKatRsp(count = "1", seed = "01".repeat(48))
    val vectors = FalconKatParser.parseRsp(rsp)
    assertEquals(2, vectors.size)
    assertEquals(0L, vectors[0].count)
    assertEquals(1L, vectors[1].count)
  }

  @Test
  fun parseRsp_skipsCommentsAndBlankLines() {
    val rsp =
        """
        |# Falcon-512
        |
        |count = 0
        |seed = ${"00".repeat(48)}
        |mlen = 0
        |msg =
        |pk = ${"00".repeat(897)}
        |sk = ${"00".repeat(1281)}
        |smlen = 1
        |sm = 00
        |
        |# end of vectors
        """
            .trimMargin()
    val vectors = FalconKatParser.parseRsp(rsp)
    assertEquals(1, vectors.size)
  }

  @Test
  fun parseRsp_rejectsMissingField() {
    // 'mlen' field intentionally omitted to trigger missing-field rejection
    val rsp =
        """
        |count = 0
        |seed = ${"00".repeat(48)}
        |msg =
        |pk = 00
        |sk = 00
        |smlen = 1
        |sm = 00
        """
            .trimMargin()
    assertFailsWith<IllegalArgumentException> { FalconKatParser.parseRsp(rsp) }
  }

  @Test
  fun parseRsp_rejectsDuplicateField() {
    val rsp =
        """
        |count = 0
        |count = 1
        |seed = ${"00".repeat(48)}
        |mlen = 0
        |msg =
        |pk = 00
        |sk = 00
        |smlen = 1
        |sm = 00
        """
            .trimMargin()
    assertFailsWith<IllegalArgumentException> { FalconKatParser.parseRsp(rsp) }
  }

  @Test
  fun parseRsp_rejectsInvalidInteger() {
    val rsp =
        """
        |count = abc
        |seed = ${"00".repeat(48)}
        |mlen = 0
        |msg =
        |pk = 00
        |sk = 00
        |smlen = 1
        |sm = 00
        """
            .trimMargin()
    assertFailsWith<IllegalStateException> { FalconKatParser.parseRsp(rsp) }
  }

  @Test
  fun parseRsp_handlesMlenZeroWithEmptyMsg() {
    val rsp =
        """
        |count = 0
        |seed = ${"00".repeat(48)}
        |mlen = 0
        |msg =
        |pk = ${"00".repeat(897)}
        |sk = ${"00".repeat(1281)}
        |smlen = 1
        |sm = 00
        """
            .trimMargin()
    val vectors = FalconKatParser.parseRsp(rsp)
    assertEquals(1, vectors.size)

    val v = vectors[0]
    assertEquals(0L, v.mlen)
    assertEquals(0, v.msg.size, "Empty msg with mlen=0 should parse as ByteArray(0)")
    assertEquals(1L, v.smlen)
  }

  @Test
  fun parseRsp_handlesSmlenZeroWithEmptySm() {
    val rsp =
        """
        |count = 0
        |seed = ${"00".repeat(48)}
        |mlen = 0
        |msg =
        |pk = ${"00".repeat(897)}
        |sk = ${"00".repeat(1281)}
        |smlen = 0
        |sm =
        """
            .trimMargin()
    val vectors = FalconKatParser.parseRsp(rsp)
    assertEquals(1, vectors.size)

    val v = vectors[0]
    assertEquals(0L, v.smlen)
    assertEquals(0, v.sm.size, "Empty sm with smlen=0 should parse as ByteArray(0)")
    assertEquals(0L, v.mlen)
  }

  // ------------------------------------------------------------------
  // loadFalconKat512Vectors tests
  // ------------------------------------------------------------------

  @Test
  fun loadFalconKat512Vectors_throwsForMissingResource() {
    // loadResourceText delegates to the classloader; a nonexistent path triggers the
    // "resource not found" error path.
    assertFailsWith<IllegalStateException> {
      loadResourceText("/falcon/nonexistent-file.rsp")
    }
  }
}

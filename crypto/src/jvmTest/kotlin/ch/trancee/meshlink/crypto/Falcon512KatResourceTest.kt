package ch.trancee.meshlink.crypto

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * Verifies that the Falcon-512 KAT .rsp resource loads correctly and produces structurally valid
 * vectors with the expected field sizes.
 *
 * Tags: @Tag("positive"), @Tag("critical-path"), @Tag("known-answer"), @Tag("smoke")
 */
@Tag("positive")
@Tag("critical-path")
@Tag("known-answer")
@Tag("smoke")
internal class Falcon512KatResourceTest {

  @Test
  fun loadKatVectorsFromRsp() {
    // Act — load all vectors from the classpath resource
    val vectors = loadFalconKat512Vectors()

    // Assert — 100 vectors, sequential counts 0..99
    assertEquals(100, vectors.size, "Expected 100 KAT vectors")

    // Single pass: per-vector invariant checks (count, field sizes, mlen/msg
    // consistency, mlen range, signature-length range)
    vectors.forEachIndexed { index, v ->
      assertEquals(index.toLong(), v.count, "Vector at index $index: count mismatch")

      assertEquals(
          FALCON512_SEED_BYTES,
          v.seed.size,
          "Vector ${v.count}: seed must be $FALCON512_SEED_BYTES bytes",
      )
      assertEquals(
          FALCON512_PK_BYTES,
          v.pk.size,
          "Vector ${v.count}: pk must be $FALCON512_PK_BYTES bytes",
      )
      assertEquals(
          FALCON512_SK_BYTES,
          v.sk.size,
          "Vector ${v.count}: sk must be $FALCON512_SK_BYTES bytes",
      )

      // msg size must equal mlen (NIST KAT invariant)
      assertEquals(
          v.mlen.toInt(),
          v.msg.size,
          "Vector ${v.count}: msg size must match mlen",
      )

      // mlen range: verified from full KAT corpus analysis (min 33, max 3300)
      assertTrue(
          v.mlen in 33L..3300L,
          "Vector ${v.count}: mlen ${v.mlen} out of expected range [33, 3300]",
      )

      // Signature length (smlen - mlen) range: verified from full KAT corpus (min 652, max 662)
      val sigLen = (v.smlen - v.mlen).toInt()
      assertTrue(
          sigLen in 652..662,
          "Vector ${v.count}: signature length $sigLen out of expected range [652, 662]",
      )
    }

    // Assert — first vector matches known KAT values
    val first = vectors[0]
    assertEquals(0L, first.count)
    assertEquals(33L, first.mlen)
    assertEquals(33, first.msg.size)
    assertEquals(691L, first.smlen)
    assertEquals(691, first.sm.size)

    // Assert — last vector structure
    val last = vectors[99]
    assertEquals(99L, last.count)
  }
}

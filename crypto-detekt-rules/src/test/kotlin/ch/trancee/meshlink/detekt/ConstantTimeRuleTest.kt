package ch.trancee.meshlink.detekt

import dev.detekt.api.Config
import dev.detekt.test.lint
import kotlin.test.Test
import kotlin.test.assertEquals

class ConstantTimeRuleTest {

  private val subject = ConstantTimeRule(Config.empty)

  @Test
  fun `branches on a secret byte are flagged`() {
    val code =
      """
      fun foo(@Secret x: Byte) {
        if (x.toInt() != 0) {
          println("leak")
        }
      }
      """.trimIndent()

    assertEquals(1, subject.lint(code).size, "data-dependent if over @Secret must be flagged")
  }

  @Test
  fun `when over a secret is flagged`() {
    val code =
      """
      fun foo(@Secret x: Byte) {
        when (x.toInt()) {
          0 -> Unit
          else -> Unit
        }
      }
      """.trimIndent()

    assertEquals(1, subject.lint(code).size, "when over @Secret must be flagged")
  }

  @Test
  fun `secret-dependent array index is flagged`() {
    val code =
      """
      fun lookup(@Secret idx: Int, table: LongArray): Long = table[idx]
      """.trimIndent()

    assertEquals(1, subject.lint(code).size, "array indexed by @Secret must be flagged")
  }

  @Test
  fun `constant-time cswap idiom is not flagged`() {
    val code =
      """
      fun cswap(a: LongArray, b: LongArray, i: Int, mask: Long) {
        val diff = a[i] xor b[i]
        a[i] = a[i] xor (diff and mask)
        b[i] = b[i] xor (diff and mask)
      }
      """.trimIndent()

    assertEquals(0, subject.lint(code).size, "constant-time bitwise cswap must not be flagged")
  }

  @Test
  fun `field engine cswap with secret parameter name does not flag constant index access`() {
    // Mirrors FieldElement.cswap: the secret name "bytes" appears in the file
    // via fromBytes, but cswap uses a non-secret `bit` parameter with a loop
    // index — no data-dependent branch or secret indexing.
    val code =
      """
      import ch.trancee.meshlink.crypto.Secret

      class FieldElement(private val limbs: LongArray) {
        fun cswap(other: FieldElement, bit: Int) {
          val mask = -bit.toLong()
          for (i in 0 until 10) {
            val diff = limbs[i] xor other.limbs[i]
            limbs[i] = limbs[i] xor (diff and mask)
            other.limbs[i] = other.limbs[i] xor (diff and mask)
          }
        }

        companion object {
          fun fromBytes(@Secret bytes: ByteArray): FieldElement {
            val h = LongArray(10)
            h[0] = bytes[0].toLong() and 0xFFL
            h[1] = bytes[1].toLong() and 0xFFL
            return FieldElement(h)
          }
        }
      }
      """.trimIndent()

    assertEquals(0, subject.lint(code).size, "field engine cswap must not be flagged")
  }

  @Test
  fun `field engine fe_mul with @Secret bytes parameter does not flag constant indexing`() {
    // fe_mul indexes by loop variables and constant positions in the limbs array —
    // the @Secret "bytes" parameter is never used as an index or branch condition.
    val code =
      """
      import ch.trancee.meshlink.crypto.Secret

      class FieldElement(private val limbs: LongArray) {
        fun mul(other: FieldElement): LongArray {
          val f0 = limbs[0]; val f1 = limbs[1]
          val g0 = other.limbs[0]; val g1 = other.limbs[1]
          val h = longArrayOf(f0 * g0, f1 * g1)
          return h
        }

        companion object {
          fun fromBytes(@Secret bytes: ByteArray): FieldElement {
            val h = LongArray(10)
            h[0] = bytes[0].toLong() and 0xFFL
            h[9] = (bytes[31].toLong() and 0x7FL) shl 2
            return FieldElement(h)
          }
        }
      }
      """.trimIndent()

    assertEquals(0, subject.lint(code).size, "field engine fe_mul must not be flagged")
  }
}

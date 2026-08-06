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
}

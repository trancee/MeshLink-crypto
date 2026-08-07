package ch.trancee.meshlink.crypto

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
class FieldElementBenchmark {

  // Pre-generated field element inputs. Values chosen to exercise the
  // carry-propagation paths: small, uniform-random, and p−1 (the largest
  // field element).
  private lateinit var smallA: FieldElement
  private lateinit var smallB: FieldElement
  private lateinit var largeA: FieldElement
  private lateinit var largeB: FieldElement
  private lateinit var pMinusOne: FieldElement

  @Setup
  fun setup() {
    smallA = FieldElement.fromBytes(leBytes(2L))
    smallB = FieldElement.fromBytes(leBytes(3L))
    largeA =
        FieldElement.fromBytes(
            hexBytes("66b3670db37d8644aedd51167c53dac407ff4068f3de3c440a3e921b4a15546a")
        )
    largeB =
        FieldElement.fromBytes(
            hexBytes("32f8b4e68f94f4df5570c409d54a0e617c8944898d1ef48f89e80a55bb469f2b")
        )
    pMinusOne =
        FieldElement.fromBytes(
            hexBytes("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        )
  }

  // ---- multiplication ----

  @Benchmark fun mulSmall(): ByteArray = smallA.mul(smallB).toBytes()

  @Benchmark fun mulLarge(): ByteArray = largeA.mul(largeB).toBytes()

  @Benchmark fun mulByPMinusOne(): ByteArray = pMinusOne.mul(pMinusOne).toBytes()

  // ---- squaring ----

  @Benchmark fun sqrSmall(): ByteArray = smallA.sqr().toBytes()

  @Benchmark fun sqrLarge(): ByteArray = largeA.sqr().toBytes()

  @Benchmark fun sqrPMinusOne(): ByteArray = pMinusOne.sqr().toBytes()

  // ---- add / sub ----

  @Benchmark fun addLarge(): ByteArray = largeA.add(largeB).normalize().toBytes()

  @Benchmark fun subLarge(): ByteArray = largeA.sub(largeB).normalize().toBytes()

  // ---- toBytes (serialisation) ----

  @Benchmark fun toBytes(): ByteArray = largeA.toBytes()

  // ---- full mul + toBytes pipeline ----

  @Benchmark fun mulAndSerialize(): ByteArray = largeA.mul(largeB).toBytes()

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  private fun leBytes(v: Long): ByteArray {
    val result = ByteArray(32)
    var remaining = v
    for (i in 0 until 8) {
      result[i] = (remaining and 0xFFL).toByte()
      remaining = remaining shr 8
    }
    return result
  }

  private fun hexBytes(s: String): ByteArray =
      ByteArray(s.length / 2) { i ->
        val hi = s[i * 2].digitToInt(16)
        val lo = s[i * 2 + 1].digitToInt(16)
        (hi shl 4 or lo).toByte()
      }
}

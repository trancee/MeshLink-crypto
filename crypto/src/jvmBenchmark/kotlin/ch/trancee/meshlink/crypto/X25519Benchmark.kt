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
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Benchmark)
class X25519Benchmark {

  // Pre-generated scalar/u-coordinate inputs at the boundaries relevant to X25519
  // (32-byte keys). Values verified against RFC 7748 §5.2 KAT vectors.
  private lateinit var katScalar1: ByteArray
  private lateinit var katScalar2: ByteArray
  private lateinit var katU1: ByteArray
  private lateinit var katU2: ByteArray
  private lateinit var basePointU: ByteArray
  private lateinit var allZeroScalar: ByteArray
  private lateinit var allOnes: ByteArray

  @Setup
  fun setup() {
    katScalar1 = hexBytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    katScalar2 = hexBytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    katU1 = hexBytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    katU2 = hexBytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    basePointU = byteArrayOf(0x09.toByte()) + ByteArray(31) { 0x00 }
    allZeroScalar = ByteArray(32)
    allOnes = ByteArray(32) { 0xFF.toByte() }
  }

  // ---- RFC 7748 KAT vectors ----

  @Benchmark fun katVector1(): ByteArray = X25519PureK.compute(katScalar1, katU1)

  @Benchmark fun katVector2(): ByteArray = X25519PureK.compute(katScalar2, katU2)

  // ---- Base-point multiplication (public key derivation) ----

  @Benchmark fun basePointMultiplication(): ByteArray = X25519PureK.compute(katScalar1, basePointU)

  // ---- Edge cases ----

  @Benchmark fun allZeroScalar(): ByteArray = X25519PureK.compute(allZeroScalar, katU1)

  @Benchmark fun allOnesScalar(): ByteArray = X25519PureK.compute(allOnes, katU1)

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  private fun hexBytes(s: String): ByteArray =
      ByteArray(s.length / 2) { i ->
        val hi = s[i * 2].digitToInt(16)
        val lo = s[i * 2 + 1].digitToInt(16)
        (hi shl 4 or lo).toByte()
      }
}

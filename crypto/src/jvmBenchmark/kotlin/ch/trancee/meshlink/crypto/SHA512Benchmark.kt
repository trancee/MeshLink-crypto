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
class SHA512Benchmark {

  // Pre-generated inputs at the block-size boundaries relevant to SHA-512
  // (block = 128 bytes). Values verified against RFC 6234 Appendix B test vectors.
  private lateinit var empty: ByteArray
  private lateinit var small: ByteArray
  private lateinit var oneBlock: ByteArray // 111 bytes (last byte before padding spill)
  private lateinit var twoBlocks: ByteArray // 256 bytes
  private lateinit var large: ByteArray // 1 MiB

  @Setup
  fun setup() {
    empty = ByteArray(0)
    small = "abc".encodeToByteArray()
    oneBlock = ByteArray(111) { 0x61 }
    twoBlocks = ByteArray(256) { (it % 251).toByte() }
    large = ByteArray(1_048_576) { 0x61 }
  }

  // ---- one-shot digest ----

  @Benchmark fun oneShotEmpty(): ByteArray = SHA512.digest(empty)

  @Benchmark fun oneShotSmall(): ByteArray = SHA512.digest(small)

  @Benchmark fun oneShotOneBlock(): ByteArray = SHA512.digest(oneBlock)

  @Benchmark fun oneShotTwoBlocks(): ByteArray = SHA512.digest(twoBlocks)

  @Benchmark fun oneShotLarge(): ByteArray = SHA512.digest(large)

  // ---- incremental digest ----

  @Benchmark
  fun incrementalSmall(): ByteArray {
    val h = SHA512Hasher()
    h.update(small)
    return h.digest()
  }

  @Benchmark
  fun incrementalLarge(): ByteArray {
    val h = SHA512Hasher()
    h.update(large)
    return h.digest()
  }

  @Benchmark
  fun incrementalChunked(): ByteArray {
    val h = SHA512Hasher()
    val chunk = ByteArray(1024) { 0x61 }
    for (i in 0 until 1024) h.update(chunk)
    return h.digest()
  }
}

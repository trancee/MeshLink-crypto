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
class SHA256Benchmark {

  // Pre-generated inputs at the block-size boundaries relevant to SHA-256
  // (block = 64 bytes). Values verified against RFC 6234 Appendix B test vectors.
  private lateinit var empty: ByteArray
  private lateinit var small: ByteArray
  private lateinit var emptyBlock: ByteArray // 64 bytes
  private lateinit var oneBlock: ByteArray // 64 bytes
  private lateinit var twoBlocks: ByteArray // 128 bytes
  private lateinit var large: ByteArray // 1 MiB

  @Setup
  fun setup() {
    empty = ByteArray(0)
    small = "abc".encodeToByteArray()
    emptyBlock = ByteArray(64) { 0x61 }
    oneBlock = "abcdbcdecdefdefghefghifghniejgefniewe".encodeToByteArray() // 36 bytes
    twoBlocks = ByteArray(128) { (it % 251).toByte() }
    large = ByteArray(1_048_576) { 0x61 }
  }

  // ---- one-shot digest ----

  @Benchmark fun oneShotEmpty(): ByteArray = SHA256.digest(empty)

  @Benchmark fun oneShotSmall(): ByteArray = SHA256.digest(small)

  @Benchmark fun oneShotOneBlock(): ByteArray = SHA256.digest(oneBlock)

  @Benchmark fun oneShotTwoBlocks(): ByteArray = SHA256.digest(twoBlocks)

  @Benchmark fun oneShotLarge(): ByteArray = SHA256.digest(large)

  // ---- incremental digest ----

  @Benchmark
  fun incrementalSmall(): ByteArray {
    val h = SHA256Hasher()
    h.update(small)
    return h.digest()
  }

  @Benchmark
  fun incrementalLarge(): ByteArray {
    val h = SHA256Hasher()
    h.update(large)
    return h.digest()
  }

  @Benchmark
  fun incrementalChunked(): ByteArray {
    val h = SHA256Hasher()
    val chunk = ByteArray(1024) { 0x61 }
    for (i in 0 until 1024) h.update(chunk)
    return h.digest()
  }
}

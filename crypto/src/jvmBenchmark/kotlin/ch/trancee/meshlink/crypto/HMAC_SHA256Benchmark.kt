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
class HMAC_SHA256Benchmark {

  // SHA-256 block size (B = 64). Key normalisation boundary: keys > 64 bytes
  // are pre-hashed. Message boundary = 55 and 57 bytes around the inner hash
  // padding spill.
  //
  // Keys chosen to exercise both normalisation branches:
  //   shortKey  — 20 bytes (≤ block: no hash)
  //   longKey   — 128 bytes (> block: pre-hash with SHA-256)
  private lateinit var shortKey: ByteArray
  private lateinit var longKey: ByteArray

  private lateinit var empty: ByteArray
  private lateinit var small: ByteArray
  private lateinit var oneBlock: ByteArray // 64 bytes
  private lateinit var twoBlocks: ByteArray // 128 bytes
  private lateinit var large: ByteArray // 1 MiB

  @Setup
  fun setup() {
    shortKey = ByteArray(20) { 0x0b }
    longKey = ByteArray(128) { (it + 1).toByte() }
    empty = ByteArray(0)
    small = "Hi There".encodeToByteArray()
    oneBlock = ByteArray(64) { (it % 251).toByte() }
    twoBlocks = ByteArray(128) { (it % 251).toByte() }
    large = ByteArray(1_048_576) { 0x61 }
  }

  // ---- one-shot digest (no key normalisation) ----

  @Benchmark fun oneShotEmpty(): ByteArray = HMAC_SHA256PureK.digest(shortKey, empty)

  @Benchmark fun oneShotSmall(): ByteArray = HMAC_SHA256PureK.digest(shortKey, small)

  @Benchmark fun oneShotOneBlock(): ByteArray = HMAC_SHA256PureK.digest(shortKey, oneBlock)

  @Benchmark fun oneShotTwoBlocks(): ByteArray = HMAC_SHA256PureK.digest(shortKey, twoBlocks)

  @Benchmark fun oneShotLarge(): ByteArray = HMAC_SHA256PureK.digest(shortKey, large)

  // ---- one-shot digest (key normalisation: key > block size) ----

  @Benchmark fun oneShotLongKey(): ByteArray = HMAC_SHA256PureK.digest(longKey, small)

  // ---- verify (digest + constant-time compare) ----

  @Benchmark
  fun verifySmall(): Boolean {
    val tag = HMAC_SHA256PureK.digest(shortKey, small)
    return HMAC_SHA256PureK.verify(shortKey, small, tag)
  }

  @Benchmark
  fun verifyLarge(): Boolean {
    val tag = HMAC_SHA256PureK.digest(shortKey, large)
    return HMAC_SHA256PureK.verify(shortKey, large, tag)
  }
}

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
class HKDF_SHA256Benchmark {

  // Input sizes that exercise HKDF's two phases:
  //   extract  — HMAC-SHA256 over IKM (bounded by IKM length)
  //   expand   — counter-driven HMAC-SHA256 chain over info
  //
  // IKM chosen to exercise SHA-256 block-boundary cases:
  //   smallIkm   — 20 bytes (within one block, no padding spill optimisation concern)
  //   oneBlock   — 64 bytes (exactly one SHA-256 block)
  //   twoBlocks  — 128 bytes (two blocks)
  //   large      — 1 MiB (many blocks)
  //
  // Output lengths exercise HKDF expand block chaining:
  //   shortOutput — 32 bytes  (one HMAC invocation, no chaining)
  //   longOutput  — 64 bytes  (two HMAC invocations, one chain step)
  //   maxOutput   — 8160 bytes (255 HMAC invocations, full chain)

  private lateinit var smallIkm: ByteArray
  private lateinit var oneBlock: ByteArray
  private lateinit var twoBlocks: ByteArray
  private lateinit var large: ByteArray

  private lateinit var emptySalt: ByteArray
  private lateinit var smallSalt: ByteArray
  private lateinit var emptyInfo: ByteArray
  private lateinit var smallInfo: ByteArray

  @Setup
  fun setup() {
    smallIkm = ByteArray(20) { 0x0b }
    oneBlock = ByteArray(64) { (it % 251).toByte() }
    twoBlocks = ByteArray(128) { (it % 251).toByte() }
    large = ByteArray(1_048_576) { 0x61 }

    emptySalt = ByteArray(0)
    smallSalt = ByteArray(16) { 0x00 }
    emptyInfo = ByteArray(0)
    smallInfo = ByteArray(10) { (it + 1).toByte() }
  }

  // ---- small IKM x short output (warm path) ----

  @Benchmark
  fun smallIkmShortOutput(): ByteArray = HKDF_SHA256.digest(smallIkm, smallSalt, smallInfo, 32)

  // ---- boundary: exactly one SHA-256 block of IKM ----

  @Benchmark
  fun oneBlockIkmShortOutput(): ByteArray = HKDF_SHA256.digest(oneBlock, smallSalt, smallInfo, 32)

  // ---- boundary: IKM spans two SHA-256 blocks ----

  @Benchmark
  fun twoBlockIkmShortOutput(): ByteArray = HKDF_SHA256.digest(twoBlocks, smallSalt, smallInfo, 32)

  // ---- large IKM ----

  @Benchmark
  fun largeIkmShortOutput(): ByteArray = HKDF_SHA256.digest(large, smallSalt, smallInfo, 32)

  // ---- output spanning multiple expand blocks ----

  @Benchmark
  fun smallIkmLongOutput(): ByteArray = HKDF_SHA256.digest(smallIkm, smallSalt, smallInfo, 64)

  @Benchmark
  fun smallIkmMaxOutput(): ByteArray = HKDF_SHA256.digest(smallIkm, smallSalt, smallInfo, 8160)

  // ---- empty salt (exercises HashLen-zeros default path) ----

  @Benchmark
  fun emptySaltShortOutput(): ByteArray = HKDF_SHA256.digest(smallIkm, emptySalt, emptyInfo, 32)

  // ---- empty IKM (exercises zero-length input path) ----

  @Benchmark
  fun emptyIkmShortOutput(): ByteArray = HKDF_SHA256.digest(ByteArray(0), smallSalt, smallInfo, 32)
}

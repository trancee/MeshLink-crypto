/*
 * Standalone SHAKE128 benchmark — designed to be run via Java directly,
 * bypassing kover instrumentation for accurate performance measurement.
 *
 * Run:
 *   ./gradlew :crypto:jvmJar
 *   java -cp crypto/build/libs/crypto-*-jvm.jar:crypto/build/classes/kotlin/jvm/test:$(find ~/.gradle -name "kotlin-stdlib-2.4.10.jar" | head -1) ch.trancee.meshlink.crypto.bench.StandaloneBenchmark
 */
package ch.trancee.meshlink.crypto.bench

import ch.trancee.meshlink.crypto.SHAKE128PureK
import kotlin.system.measureNanoTime

class StandaloneBenchmark {
  companion object {
    @JvmStatic
    fun main(args: Array<String>) {
      val inputSize = 65536
      val iters = 1000
      val warmup = 5000
      val input = ByteArray(inputSize) { 0x61.toByte() }

      // Warmup — JVM JIT compilation (C1 then C2 tier-up)
      repeat(warmup) { SHAKE128PureK.digest(input, 64) }

      // Measured run
      val elapsed = measureNanoTime {
        repeat(iters) { SHAKE128PureK.digest(input, 64) }
      }

      val perOpUs = (elapsed.toDouble() / iters) / 1000.0
      val mbps = (inputSize / 1024.0 / 1024.0) / (perOpUs / 1_000_000.0)
      val metric = "METRIC shake128_throughput_mbps=${"%.2f".format(mbps)}"

      println(metric)
      println(
          "BENCH | input=${inputSize}B | ${"%.2f".format(perOpUs)} us/op | ${"%.2f".format(mbps)} MB/s"
      )

      java.io.File("build/ar-benchmark-output.txt").writeText(metric + "\n")
    }
  }
}

/*
 * SPDX-License-Identifier: Apache-2.0
 * Autoresearch benchmark harness for comparing SHAKE128 throughput.
 *
 * Measures the pure-Kotlin Keccak-f[1600] permutation performance in MeshLink-crypto
 * against the KotlinCrypto/sponges approach (local-variable unrolled permutation).
 *
 * Output: a single line `METRIC shake128_throughput_mbps=<value>` parseable by autoresearch.sh
 */
package ch.trancee.meshlink.crypto

import kotlin.system.measureNanoTime
import kotlin.test.Test

class ArBenchmark {
  @Test
  fun benchShake128Throughput() {
    val inputSize = 65536
    val iters = 500
    val warmup = 500
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

    // Write metric to file for autoresearch.sh to read (Gradle may suppress stdout)
    java.io.File("build/ar-benchmark-output.txt").writeText(metric + "\n")
  }
}

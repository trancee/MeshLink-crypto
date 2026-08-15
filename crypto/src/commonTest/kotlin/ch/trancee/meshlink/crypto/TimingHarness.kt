package ch.trancee.meshlink.crypto

import kotlin.time.Duration
import kotlin.time.TimeSource

/**
 * Per-target timing-variance test scaffold (ADR-0003, ticket 02, seam 3).
 *
 * Runs a [block] over a set of varied secret inputs and records per-input timing samples. No
 * statistical assertion is made — the harness simply ensures the pure-K path is exercised over
 * varied secrets on every target so that timing-class regressions at least execute in CI. The
 * constant-time *proof* lives in reasoning + Wycheproof + this harness, not in coverage (ADR-0003
 * §4).
 *
 * Intended for Wycheproof-routed use: each primitive's test feeds this harness the `tc` (test case)
 * input bytes from its Wycheproof vectors and the primitive's pure-K entry point, producing one
 * [Sample] per input.
 *
 * Example:
 * ```
 * TimingHarness().measure(
 *   label = "SHA-256",
 *   inputs = wycheproofTcInputs,
 *   block = { SHA256PureK.digest(it) },
 * )
 * ```
 */
class TimingHarness {
  /** One timing sample for a single input execution. */
  data class Sample(
      val label: String,
      val inputBytes: Int,
      val iterations: Int,
      val totalDuration: Duration,
  )

  private val samples = mutableListOf<Sample>()

  /**
   * Runs [block] over each [inputs], repeated [iterations] times per input, recording the total
   * wall-clock duration per input. No assertion on variance — just records.
   *
   * @param label Human-readable name of the primitive/operation under test.
   * @param inputs Vary secret inputs (e.g. Wycheproof `tc.input` fields).
   * @param iterations Number of times [block] is invoked per input. Default 1000 so sub-microsecond
   *   per-call variance is observable without a statistical claim.
   * @param warmup Number of untimed invocations per input to run before measurement begins. Warms
   *   up JIT/CPU caches so the first sample isn't a cold-start outlier. Default 300. Pass 0 to
   *   disable.
   * @param block The pure-K operation to time. Must be no-throw.
   */
  fun measure(
      label: String,
      inputs: List<ByteArray>,
      iterations: Int = 1000,
      warmup: Int = 300,
      block: (ByteArray) -> Unit,
  ) {
    if (warmup > 0) {
      inputs.forEach { input -> repeat(warmup) { block(input) } }
    }
    inputs.forEach { input ->
      val mark = TimeSource.Monotonic.markNow()
      repeat(iterations) { block(input) }
      val elapsed = mark.elapsedNow()
      samples.add(Sample(label, input.size, iterations, elapsed))
    }
  }

  /** All recorded samples, in measurement order. */
  fun samples(): List<Sample> = samples.toList()

  /** Clears all recorded samples. */
  fun reset() {
    samples.clear()
  }

  /**
   * Asserts that timing variance across all recorded samples for [label] is within [maxRatio] of
   * the median duration — a coarse constant-time violation detector (ADR-0003 §4).
   *
   * Computes max / median across all matching samples. A ratio near 1.0 indicates low timing
   * variance; a ratio exceeding [maxRatio] indicates potential input-dependent timing leakage. This
   * is necessary (but not sufficient) for constant-time: it does not prove constant-time execution.
   *
   * Default threshold of 3.0 accommodates typical CI jitter (JIT warmup, GC pauses, OS scheduling)
   * on JVM/Android while flagging obvious timing leaks (e.g. secret- dependent branches causing 3×+
   * slowdown for some inputs).
   *
   * @param label Human-readable name of the operation under test.
   * @param maxRatio Maximum allowed ratio of longest sample to median sample duration.
   * @return The observed max/median ratio, or 1.0 when durations are too small to measure
   * @throws AssertionError if the ratio exceeds [maxRatio].
   * @throws IllegalArgumentException if fewer than 2 samples exist for [label].
   */
  fun assertConstantTime(label: String, maxRatio: Double = 3.0): Double {
    val matching = samples.filter { it.label == label }
    require(matching.size >= 2) {
      "Need at least 2 samples with label '$label' to assert constant-time"
    }
    val medianNanos =
        matching
            .map { it.totalDuration.inWholeNanoseconds }
            .sorted()
            .let { sorted ->
              if (sorted.size % 2 == 0) {
                (sorted[sorted.size / 2 - 1] + sorted[sorted.size / 2]) / 2.0
              } else {
                sorted[sorted.size / 2].toDouble()
              }
            }
    val maxNanos = matching.maxOf { it.totalDuration.inWholeNanoseconds }
    // Guard: if durations are too small to measure (median truncates to 0 ns),
    // we cannot detect timing variance. Return 1.0 (no measurable variance).
    if (medianNanos <= 0.0) {
      return 1.0
    }
    val ratio = maxNanos.toDouble() / medianNanos
    if (ratio > maxRatio) {
      throw AssertionError(
          "Timing variance for '$label' exceeds constant-time bound: " +
              "max=$maxNanos ns, median=$medianNanos ns, ratio=$ratio > $maxRatio"
      )
    }
    return ratio
  }
}

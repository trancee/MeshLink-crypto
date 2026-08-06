package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TimingHarnessTest {
  @Test
  fun `timing harness records one sample per varied input`() {
    val harness = TimingHarness()
    // A trivial constant-time operation over varied secret inputs.
    // No statistical assertion — just ensures the harness runs and records.
    harness.measure(
        label = "dummy-constant",
        inputs =
            listOf(
                ByteArray(32) { 0x01 },
                ByteArray(32) { 0x02 },
                ByteArray(32) { 0x03 },
            ),
        iterations = 100,
    ) { input ->
      // Constant-time XOR-fold: no secret-dependent branch, no secret-indexed access.
      var acc = 0
      input.forEach { acc = acc xor it.toInt() }
    }
    val recorded = harness.samples()
    assertEquals(3, recorded.size, "one sample per input")
    assertTrue(recorded.all { it.iterations == 100 }, "iterations recorded per sample")
    assertTrue(recorded.all { it.totalDuration.isPositive() }, "duration recorded per sample")
  }

  @Test
  fun `reset clears recorded samples`() {
    val harness = TimingHarness()
    harness.measure(
        label = "t",
        inputs = listOf(ByteArray(1) { 0 }),
        iterations = 1,
    ) { _ ->
    }
    assertEquals(1, harness.samples().size)
    harness.reset()
    assertTrue(harness.samples().isEmpty())
  }
}

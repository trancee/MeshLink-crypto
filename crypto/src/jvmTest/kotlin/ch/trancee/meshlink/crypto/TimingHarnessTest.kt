package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

class TimingHarnessTest {
  @Tag("positive")
  @Tag("security")
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

  @Tag("positive")
  @Tag("security")
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

  @Tag("positive")
  @Tag("timing")
  @Tag("security")
  @Test
  fun `assertConstantTime passes for constant-time operation`() {
    val harness = TimingHarness()
    harness.measure(
        label = "constant-op",
        inputs =
            listOf(
                ByteArray(32) { 0x01 },
                ByteArray(32) { 0x02 },
                ByteArray(32) { 0x03 },
            ),
        iterations = 1000,
    ) { input ->
      var acc = 0
      input.forEach { acc = acc xor it.toInt() }
    }
    // Constant-time operation should have low variance ratio.
    // Using a generous threshold to avoid CI flakiness.
    val ratio = harness.assertConstantTime(label = "constant-op", maxRatio = 10.0)
    assertTrue(ratio < 10.0, "ratio $ratio should be within threshold")
  }

  @Tag("positive")
  @Tag("timing")
  @Tag("security")
  @Test
  fun `assertConstantTime fails for variable-time operation`() {
    val harness = TimingHarness()
    // Simulate a timing leak: one input takes 10x longer than others.
    val fast = ByteArray(32) { 0x01 }
    val slow = ByteArray(32) { 0x02 }
    harness.measure(
        label = "variable-op",
        inputs = listOf(fast, slow),
        iterations = 1,
    ) { input ->
      if (input[0] == 0x02.toByte()) {
        Thread.sleep(50)
      }
    }
    assertFailsWith<AssertionError> {
      harness.assertConstantTime(label = "variable-op", maxRatio = 1.5)
    }
  }

  @Tag("positive")
  @Tag("timing")
  @Tag("security")
  @Test
  fun `assertConstantTime requires at least two samples`() {
    val harness = TimingHarness()
    harness.measure(label = "single", inputs = listOf(ByteArray(1)), iterations = 1) { _ -> }
    assertFailsWith<IllegalArgumentException> {
      harness.assertConstantTime(label = "single")
    }
  }
}

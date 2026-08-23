# Benchmarking Convention

## Overview

Every change to a cryptographic primitive's implementation (constant-time logic,
round functions, field arithmetic, permutation steps) **must** include a before/after
benchmark comparison. This is a **hard requirement** -- not optional.

## When to benchmark

Benchmark whenever you modify the **implementation** of a primitive:

- Round constants (e.g. SHAKE256 RC[16] fix)
- Field arithmetic (e.g. Montgomery reduction, cswap)
- Permutation steps (e.g. theta, rho+pi, chi, iota)
- State update functions
- Any change that could affect CPU instruction count or data flow

Benchmark is **not** required for:

- Test-only changes (fixing expected values, adding test cases)
- Documentation-only changes
- Build configuration changes (unless the change affects compilation flags)
- Adding new public API surface that delegates to unchanged internals

## How to benchmark

### Option A: Existing TimingHarness (preferred)

If the primitive already has a `@Tag("timing")` test, run it with:

```bash
./gradlew :crypto:jvmTest \
    --tests "ch.trancee.meshlink.crypto.<PrimitiveName>Test" \
    --rerun-tasks --no-build-cache --info 2>&1 | grep "<PRIMITIVE>"
```

### Option B: Temporary benchmark (when no timing test exists)

Create a temporary file `crypto/src/jvmTest/kotlin/ch/trancee/meshlink/crypto/Temp<Primitive>Benchmark.kt`:

```kotlin
package ch.trancee.meshlink.crypto

import kotlin.system.measureNanoTime
import kotlin.test.Test

class Temp<Primitive>Benchmark {
  @Test
  fun bench() {
    val sizes = listOf(0, 64, 135, 136, 137, 272, 273, 1024, 4096, 65536, 1_000_000)

    for (size in sizes) {
      val iters = if (size <= 1024) 10_000 else if (size <= 65536) 1_000 else 10
      val input = if (size == 0) byteArrayOf() else ByteArray(size) { 0x61 }
      val warmup = if (size <= 1024) 1000 else 10
      repeat(warmup) { <Primitive>Impl.digest(input) }
      val elapsed = measureNanoTime {
        repeat(iters) { <Primitive>Impl.digest(input) }
      }
      val perOpUs = (elapsed / iters) / 1000.0
      val mbps = if (size > 0) (size / 1024.0 / 1024.0) / (perOpUs / 1_000_000.0) else 0.0
      println("BENCH | input=${size}B | ${perOpUs} us/op | ${mbps} MB/s")
    }
  }
}
```

Run twice -- once with the **buggy** version (`git stash` the fix), once with the
**fixed** version (restore the fix). Delete the temporary file after.

## What to benchmark

Include **at least** these input sizes to cover:

- Empty input (0 bytes)
- Small input (3-64 bytes)
- Sub-block boundary (135 bytes = rate-1)
- Block boundary (136 bytes = rate)
- Post-block (137 bytes = rate+1)
- Two-block boundary (272-273 bytes)
- Medium (1024, 4096 bytes)
- Large (65536, 1000000 bytes)

Output length: 64 bytes (standard SHAKE256 output).

## How to present results

Present results in a Markdown table comparing **before** (buggy) vs. **after**
(fixed). The **Difference** column goes at the end of the table
(pct = (after-before)/before * 100):

| Input Size | Before (us/op) | After (us/op) | Before (MB/s) | After (MB/s) | Difference |
|---|---|---|---|---|---|
| 0 B | 13.49 | 6.10 | -- | -- | +/- noise |
| 64 B | 5.70 | 5.33 | 10.7 | 11.4 | -6.5% (:warning:) |

**Rules for Markdown tables in PR comments**:

- The separator row (`|---|...`) must have the same number of columns as the
  header row. GitHub silently fails to render tables with mismatched column
  counts. Count the pipes.
- Use plain ASCII in PR comment tables. Avoid Unicode operators like mu (us) or
  em dash (--). Use `us` and `--` instead.
- Flag rows where pct exceeds the +/-5% noise threshold with `:warning:` in the
  Difference column. This makes potential regressions easy to spot at a glance.
- The 0 B (empty input) row should be marked `±noise` since warm-up jitter
  dominates at zero input size (no throughput).

If all rows are within the +/-5% noise threshold, state that the change is
performance-neutral.

## How to document

1. Add a **comment to the PR** with the before/after comparison table.
2. Include a `Skills Used` summary in the completion report.
3. Reference the benchmark in the commit message if performance is a concern.

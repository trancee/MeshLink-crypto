/*
 * Known-answer test for keccakF1600 permutation on a zero state.
 *
 * Verifies all 25 output lanes against the XKCP reference
 * (KeccakP1600_Permute applied to all-zero state). lane[0] = 0xF1258F7940E1DDE7
 * is the canonical XKCP SimpleFIPS202.c zero-state value.
 *
 * [ADR-0003](docs/adr/0003-verification-gates.md) §1 — this test guards the
 * round constants and permutation structure against unrolled-loop regressions.
 */
package ch.trancee.meshlink.crypto

import java.lang.Long.parseUnsignedLong
import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.Tag

@Tag("positive")
@Tag("critical-path")
internal class KeccakF1600ZeroStateTest {

  private val xkcpZeroState =
      longArrayOf(
          parseUnsignedLong("f1258f7940e1dde7", 16),
          parseUnsignedLong("84d5ccf933c0478a", 16),
          parseUnsignedLong("d598261ea65aa9ee", 16),
          parseUnsignedLong("bd1547306f80494d", 16),
          parseUnsignedLong("8b284e056253d057", 16),
          parseUnsignedLong("ff97a42d7f8e6fd4", 16),
          parseUnsignedLong("90fee5a0a44647c4", 16),
          parseUnsignedLong("8c5bda0cd6192e76", 16),
          parseUnsignedLong("ad30a6f71b19059c", 16),
          parseUnsignedLong("30935ab7d08ffc64", 16),
          parseUnsignedLong("eb5aa93f2317d635", 16),
          parseUnsignedLong("a9a6e6260d712103", 16),
          parseUnsignedLong("81a57c16dbcf555f", 16),
          parseUnsignedLong("43b831cd0347c826", 16),
          parseUnsignedLong("01f22f1a11a5569f", 16),
          parseUnsignedLong("05e5635a21d9ae61", 16),
          parseUnsignedLong("64befef28cc970f2", 16),
          parseUnsignedLong("613670957bc46611", 16),
          parseUnsignedLong("b87c5a554fd00ecb", 16),
          parseUnsignedLong("8c3ee88a1ccf32c8", 16),
          parseUnsignedLong("940c7922ae3a2614", 16),
          parseUnsignedLong("1841f924a2c509e4", 16),
          parseUnsignedLong("16f53526e70465c2", 16),
          parseUnsignedLong("75f644e97f30a13b", 16),
          parseUnsignedLong("eaf1ff7b5ceca249", 16),
      )

  @Test
  fun keccakF1600ZeroState() {
    val state = LongArray(25)
    keccakF1600(state)
    for (i in 0..24) {
      assertEquals(
          xkcpZeroState[i],
          state[i],
          "lane[$i] mismatch",
      )
    }
  }
}

/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Known-answer tests for FalconFpr — the integer-only IEEE 754 binary64 emulation
 * (PQClean fpr.h / fpr.c port). Uses java.lang.Double.doubleToRawLongBits for
 * IEEE 754 bit-pattern verification against the JVM's hardware FP.
 *
 * NOTE: fpr_rint, fpr_floor, fpr_trunc return int64_t (plain integers), NOT
 * fpr values. fpr_ursh/fpr_irsh/fpr_ulsh operate on raw 64-bit values (not
 * IEEE 754 arithmetic).
 */
package ch.trancee.meshlink.crypto

import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("positive")
@Tag("critical-path")
@Tag("known-answer")
internal class FalconFprTest {

  // === Helpers ===

  private fun d2l(d: Double): Long = java.lang.Double.doubleToRawLongBits(d)

  private fun l2d(l: Long): Double = java.lang.Double.longBitsToDouble(l)

  private fun assertFprEquals(expected: Double, actual: Long, msg: String = "") {
    assertEquals(d2l(expected), actual, "Expected fpr($expected) but got fpr(${l2d(actual)}). $msg")
  }

  private fun assertFprApprox(expected: Double, actual: Long, bits: Long = 1L, msg: String = "") {
    val expectedBits = d2l(expected)
    val actualBits = actual
    val diff =
        if (expectedBits > actualBits) expectedBits - actualBits else actualBits - expectedBits
    assertTrue(
        diff <= bits,
        "Expected fpr($expected) ≈ fpr(${l2d(actual)}) within $bits bit(s). $msg",
    )
  }

  // === Constants ===

  @Test
  @Tag("critical-path")
  fun `constants match IEEE 754 binary64 encoding`() {
    assertEquals(d2l(1.0), FalconFpr.fpr_one, "fpr_one must be 1.0")
    assertEquals(d2l(2.0), FalconFpr.fpr_two, "fpr_two must be 2.0")
    assertEquals(d2l(0.5), FalconFpr.fpr_onehalf, "fpr_onehalf must be 0.5")
    assertEquals(0L, FalconFpr.fpr_zero, "fpr_zero must be 0")
  }

  @Test
  @Tag("critical-path")
  fun `inv_sqrt constants are correct`() {
    assertFprApprox(1.0 / Math.sqrt(2.0), FalconFpr.fpr_invsqrt2, 1L, "fpr_invsqrt2")
    assertFprApprox(1.0 / Math.sqrt(8.0), FalconFpr.fpr_invsqrt8, 1L, "fpr_invsqrt8")
  }

  // === Tables ===

  @Test
  fun `fpr_gm_tab has 2046 entries`() {
    assertEquals(2046, FalconFpr.fpr_gm_tab.size)
  }

  @Test
  fun `fpr_p2_tab has 11 entries`() {
    assertEquals(11, FalconFpr.fpr_p2_tab.size)
  }

  @Test
  fun `fpr_inv_sigma has 11 entries`() {
    assertEquals(11, FalconFpr.fpr_inv_sigma.size)
  }

  @Test
  fun `fpr_sigma_min has 11 entries`() {
    assertEquals(11, FalconFpr.fpr_sigma_min.size)
  }

  // === Shift helpers ===
  // These operate on raw 64-bit values, NOT IEEE 754 doubles

  @Test
  @Tag("critical-path")
  fun `fpr_ursh shifts unsigned by small and large counts`() {
    val x = d2l(8.0)
    assertEquals(x.ushr(1), FalconFpr.fpr_ursh(x, 1), "fpr_ursh(x, 1)")
    assertEquals(x.ushr(32), FalconFpr.fpr_ursh(x, 32), "fpr_ursh(x, 32)")
    assertEquals(x.ushr(40), FalconFpr.fpr_ursh(x, 40), "fpr_ursh(x, 40)")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_irsh shifts signed by small and large counts`() {
    val x = d2l(-8.0)
    assertEquals(x.shr(1), FalconFpr.fpr_irsh(x, 1), "fpr_irsh(x, 1)")
    assertEquals(x.shr(32), FalconFpr.fpr_irsh(x, 32), "fpr_irsh(x, 32)")
    assertEquals(x.shr(40), FalconFpr.fpr_irsh(x, 40), "fpr_irsh(x, 40)")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_ulsh shifts unsigned by small and large counts`() {
    val x = d2l(1.0)
    assertEquals(x.shl(1), FalconFpr.fpr_ulsh(x, 1), "fpr_ulsh(x, 1)")
    assertEquals(x.shl(32), FalconFpr.fpr_ulsh(x, 32), "fpr_ulsh(x, 32)")
    assertEquals(x.shl(40), FalconFpr.fpr_ulsh(x, 40), "fpr_ulsh(x, 40)")
  }

  // === fprNorm64 ===
  // Returns (normalized_mantissa, adjusted_exponent) where mantissa is in 2^62..2^63 range

  @Test
  @Tag("critical-path")
  fun `fprNorm64 normalizes mantissa to top-bit position`() {
    val (m, e) = FalconFpr.fprNorm64(1L, 9)
    // fprNorm64 shifts m left to set bit 63, starting ee = 9 - 63 = -54
    // For m=1, all high-bit checks are 0, so ee stays at -54
    assertEquals(1L, m.ushr(63), "Normalized top bit should be set")
    assertEquals(-54, e, "Exponent should be -54 (ee starts at 9-63=-54)")
    assertEquals(1L shl 63, m)
  }

  @Test
  fun `fprNorm64 handles already-normalized value`() {
    val m = 1L shl 62
    val (nm, _ne) = FalconFpr.fprNorm64(m, 5)
    // nm should be 2^63 (Long.MIN_VALUE as signed), compare unsigned
    assertEquals(1L, nm.ushr(63), "Normalized top bit should be set")
  }

  // === FPR ===

  @Test
  @Tag("critical-path")
  fun `FPR constructs 2 from exponent and mantissa`() {
    // fpr_of(2) goes through FPR(0, -53, 2^54) → 2.0
    val result = FalconFpr.FPR(0, -53, 1L shl 54)
    assertFprEquals(2.0, result, "FPR(0, -53, 2^54) should be 2.0")
  }

  @Test
  fun `FPR zeros result when exponent is too low`() {
    val result = FalconFpr.FPR(0, -1077, 1L shl 54)
    assertEquals(0L, result, "FPR with exponent below -1076 should produce zero")
  }

  @Test
  fun `FPR zeros exponent when mantissa is zero`() {
    val result = FalconFpr.FPR(0, 0, 0L)
    assertEquals(0L, result, "FPR(0, 0, 0) should produce +0.0")
  }

  @Test
  fun `FPR preserves sign when result is zero`() {
    val result = FalconFpr.FPR(1, 0, 0L)
    assertEquals(d2l(-0.0), result, "FPR(1, 0, 0) should produce -0.0")
  }

  // === fpr_of / fpr_scaled ===

  @Test
  @Tag("critical-path")
  fun `fpr_of converts integers to IEEE 754 correctly`() {
    assertFprEquals(0.0, FalconFpr.fpr_of(0L), "fpr_of(0) must be 0.0")
    assertFprEquals(1.0, FalconFpr.fpr_of(1L), "fpr_of(1) must be 1.0")
    assertFprEquals(2.0, FalconFpr.fpr_of(2L), "fpr_of(2) must be 2.0")
    assertFprEquals(3.0, FalconFpr.fpr_of(3L), "fpr_of(3) must be 3.0")
    assertFprEquals(255.0, FalconFpr.fpr_of(255L), "fpr_of(255) must be 255.0")
    assertFprEquals(1024.0, FalconFpr.fpr_of(1024L), "fpr_of(1024) must be 1024.0")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_of handles negative integers`() {
    assertFprEquals(-1.0, FalconFpr.fpr_of(-1L), "fpr_of(-1) must be -1.0")
    assertFprEquals(-2.0, FalconFpr.fpr_of(-2L), "fpr_of(-2) must be -2.0")
    assertFprEquals(-3.0, FalconFpr.fpr_of(-3L), "fpr_of(-3) must be -3.0")
    assertFprEquals(-100.0, FalconFpr.fpr_of(-100L), "fpr_of(-100) must be -100.0")
  }

  @Test
  fun `fpr_scaled applies bias correctly`() {
    assertFprEquals(1.0, FalconFpr.fpr_scaled(1L, 0), "fpr_scaled(1, 0) must be 1.0")
    assertFprEquals(2.0, FalconFpr.fpr_scaled(1L, 1), "fpr_scaled(1, 1) must be 2.0")
    assertFprEquals(3.0, FalconFpr.fpr_scaled(3L, 0), "fpr_scaled(3, 0) must be 3.0")
  }

  // === fpr_rint ===
  // Returns int64_t (integer), NOT fpr

  @Test
  @Tag("critical-path")
  fun `fpr_rint rounds to nearest even`() {
    assertEquals(1L, FalconFpr.fpr_rint(d2l(1.4)), "rint(1.4) = 1")
    assertEquals(2L, FalconFpr.fpr_rint(d2l(1.6)), "rint(1.6) = 2")
    assertEquals(2L, FalconFpr.fpr_rint(d2l(2.5)), "rint(2.5) = 2 (even)")
    assertEquals(2L, FalconFpr.fpr_rint(d2l(1.5)), "rint(1.5) = 2 (even)")
    assertEquals(4L, FalconFpr.fpr_rint(d2l(3.5)), "rint(3.5) = 4 (even)")
  }

  @Test
  fun `fpr_rint rounds negative values`() {
    assertEquals(-1L, FalconFpr.fpr_rint(d2l(-1.4)), "rint(-1.4) = -1")
    assertEquals(-2L, FalconFpr.fpr_rint(d2l(-1.6)), "rint(-1.6) = -2")
    assertEquals(-2L, FalconFpr.fpr_rint(d2l(-2.5)), "rint(-2.5) = -2 (even)")
  }

  @Test
  fun `fpr_rint clamps very small values to zero`() {
    // 0.1 has e = 62 (1085 - 1023), e >= 64 → mantissa zeroed
    assertEquals(0L, FalconFpr.fpr_rint(d2l(0.1)), "rint(0.1) = 0")
  }

  @Test
  fun `fpr_rint handles zero input`() {
    assertEquals(0L, FalconFpr.fpr_rint(0L), "rint(0) = 0")
  }

  // === fpr_floor ===
  // Returns int64_t (integer), NOT fpr

  @Test
  @Tag("critical-path")
  fun `fpr_floor rounds toward minus infinity`() {
    assertEquals(1L, FalconFpr.fpr_floor(d2l(1.5)), "floor(1.5) = 1")
    assertEquals(1L, FalconFpr.fpr_floor(d2l(1.9)), "floor(1.9) = 1")
    assertEquals(2L, FalconFpr.fpr_floor(d2l(2.0)), "floor(2.0) = 2")
    assertEquals(-2L, FalconFpr.fpr_floor(d2l(-1.5)), "floor(-1.5) = -2")
    assertEquals(-2L, FalconFpr.fpr_floor(d2l(-1.1)), "floor(-1.1) = -2")
    assertEquals(-1L, FalconFpr.fpr_floor(d2l(-0.5)), "floor(-0.5) = -1")
  }

  @Test
  fun `fpr_floor clamps very small values`() {
    assertEquals(0L, FalconFpr.fpr_floor(d2l(0.1)), "floor(0.1) = 0")
  }

  @Test
  fun `fpr_floor of zero is zero`() {
    assertEquals(0L, FalconFpr.fpr_floor(0L), "floor(0) = 0")
  }

  // === fpr_trunc ===
  // Returns int64_t (integer), NOT fpr

  @Test
  @Tag("critical-path")
  fun `fpr_trunc rounds toward zero`() {
    assertEquals(1L, FalconFpr.fpr_trunc(d2l(1.5)), "trunc(1.5) = 1")
    assertEquals(1L, FalconFpr.fpr_trunc(d2l(1.9)), "trunc(1.9) = 1")
    assertEquals(-1L, FalconFpr.fpr_trunc(d2l(-1.5)), "trunc(-1.5) = -1")
    assertEquals(-1L, FalconFpr.fpr_trunc(d2l(-1.9)), "trunc(-1.9) = -1")
    assertEquals(2L, FalconFpr.fpr_trunc(d2l(2.0)), "trunc(2.0) = 2")
  }

  @Test
  fun `fpr_trunc clamps very small values`() {
    assertEquals(0L, FalconFpr.fpr_trunc(d2l(0.1)), "trunc(0.1) = 0")
  }

  @Test
  fun `fpr_trunc of zero is zero`() {
    assertEquals(0L, FalconFpr.fpr_trunc(0L), "trunc(0) = 0")
  }

  // === fpr_add ===
  // Returns fpr (IEEE 754 double), NOT integer

  @Test
  @Tag("critical-path")
  fun `fpr_add performs IEEE 754 addition`() {
    assertFprEquals(3.0, FalconFpr.fpr_add(d2l(1.0), d2l(2.0)), "1+2=3")
    assertFprEquals(5.0, FalconFpr.fpr_add(d2l(2.0), d2l(3.0)), "2+3=5")
    assertFprEquals(6.0, FalconFpr.fpr_add(d2l(3.0), d2l(3.0)), "3+3=6")
    assertFprEquals(10.0, FalconFpr.fpr_add(d2l(7.0), d2l(3.0)), "7+3=10")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_add handles subtraction via different signs`() {
    assertFprEquals(1.0, FalconFpr.fpr_add(d2l(3.0), d2l(-2.0)), "3+(-2)=1")
    assertFprEquals(-1.0, FalconFpr.fpr_add(d2l(1.0), d2l(-2.0)), "1+(-2)=-1")
    assertFprEquals(0.0, FalconFpr.fpr_add(d2l(1.0), d2l(-1.0)), "1+(-1)=0")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_add handles zeros`() {
    assertFprEquals(2.0, FalconFpr.fpr_add(d2l(0.0), d2l(2.0)), "0+2=2")
    assertFprEquals(2.0, FalconFpr.fpr_add(d2l(2.0), d2l(0.0)), "2+0=2")
  }

  @Test
  fun `fpr_add same-magnitude opposite-sign cancels to zero`() {
    val result = FalconFpr.fpr_add(d2l(5.0), d2l(-5.0))
    assertEquals(0L, result, "5+(-5) should be +0.0")
  }

  @Test
  fun `fpr_add is commutative for same-sign operands`() {
    val a = d2l(3.0)
    val b = d2l(7.0)
    assertEquals(FalconFpr.fpr_add(a, b), FalconFpr.fpr_add(b, a), "fpr_add commutative")
  }

  // === fpr_sub ===

  @Test
  @Tag("critical-path")
  fun `fpr_sub performs IEEE 754 subtraction`() {
    assertFprEquals(1.0, FalconFpr.fpr_sub(d2l(3.0), d2l(2.0)), "3-2=1")
    assertFprEquals(-1.0, FalconFpr.fpr_sub(d2l(2.0), d2l(3.0)), "2-3=-1")
    assertFprEquals(6.0, FalconFpr.fpr_sub(d2l(8.0), d2l(2.0)), "8-2=6")
  }

  @Test
  fun `fpr_sub with negative result`() {
    assertFprEquals(-5.0, FalconFpr.fpr_sub(d2l(2.0), d2l(7.0)), "2-7=-5")
  }

  // === fpr_neg ===

  @Test
  @Tag("critical-path")
  fun `fpr_neg flips sign`() {
    assertFprEquals(-1.0, FalconFpr.fpr_neg(d2l(1.0)), "fpr_neg(1) = -1")
    assertFprEquals(1.0, FalconFpr.fpr_neg(d2l(-1.0)), "fpr_neg(-1) = 1")
    assertFprEquals(-2.5, FalconFpr.fpr_neg(d2l(2.5)), "fpr_neg(2.5) = -2.5")
    assertEquals(d2l(-0.0), FalconFpr.fpr_neg(d2l(0.0)), "fpr_neg(+0) should be -0")
    assertEquals(d2l(0.0), FalconFpr.fpr_neg(d2l(-0.0)), "fpr_neg(-0) should be +0")
  }

  // === fpr_half ===

  @Test
  @Tag("critical-path")
  fun `fpr_half divides by 2`() {
    assertFprEquals(0.5, FalconFpr.fpr_half(d2l(1.0)), "half(1)=0.5")
    assertFprEquals(1.0, FalconFpr.fpr_half(d2l(2.0)), "half(2)=1")
    assertFprEquals(2.0, FalconFpr.fpr_half(d2l(4.0)), "half(4)=2")
    assertFprEquals(-1.0, FalconFpr.fpr_half(d2l(-2.0)), "half(-2)=-1")
  }

  @Test
  fun `fpr_half of zero remains zero`() {
    assertEquals(0L, FalconFpr.fpr_half(0L), "fpr_half(0) should be 0")
  }

  // === fpr_double ===

  @Test
  @Tag("critical-path")
  fun `fpr_double multiplies by 2`() {
    assertFprEquals(2.0, FalconFpr.fpr_double(d2l(1.0)), "double(1)=2")
    assertFprEquals(4.0, FalconFpr.fpr_double(d2l(2.0)), "double(2)=4")
    assertFprEquals(8.0, FalconFpr.fpr_double(d2l(4.0)), "double(4)=8")
    assertFprEquals(-2.0, FalconFpr.fpr_double(d2l(-1.0)), "double(-1)=-2")
  }

  @Test
  fun `fpr_double of zero remains zero`() {
    assertEquals(0L, FalconFpr.fpr_double(0L), "fpr_double(0) should be 0")
  }

  // === fpr_mul ===

  @Test
  @Tag("critical-path")
  fun `fpr_mul performs IEEE 754 multiplication`() {
    assertFprApprox(6.0, FalconFpr.fpr_mul(d2l(2.0), d2l(3.0)), 0L, "2*3=6")
    assertFprApprox(12.0, FalconFpr.fpr_mul(d2l(3.0), d2l(4.0)), 0L, "3*4=12")
    assertFprApprox(0.5, FalconFpr.fpr_mul(d2l(2.0), d2l(0.25)), 0L, "2*0.25=0.5")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_mul handles negative operands`() {
    assertFprApprox(-6.0, FalconFpr.fpr_mul(d2l(-2.0), d2l(3.0)), 0L, "-2*3=-6")
    assertFprApprox(6.0, FalconFpr.fpr_mul(d2l(-2.0), d2l(-3.0)), 0L, "-2*-3=6")
  }

  @Test
  fun `fpr_mul by zero produces zero`() {
    val result = FalconFpr.fpr_mul(d2l(5.0), d2l(0.0))
    assertEquals(0L, result, "5*0 should be 0")
  }

  @Test
  fun `fpr_mul is commutative`() {
    val a = d2l(2.0)
    val b = d2l(3.0)
    assertEquals(FalconFpr.fpr_mul(a, b), FalconFpr.fpr_mul(b, a), "fpr_mul commutative")
  }

  // === fpr_sqr ===

  @Test
  @Tag("critical-path")
  fun `fpr_sqr squares correctly`() {
    assertFprApprox(4.0, FalconFpr.fpr_sqr(d2l(2.0)), 0L, "2^2=4")
    assertFprApprox(9.0, FalconFpr.fpr_sqr(d2l(3.0)), 0L, "3^2=9")
    assertFprApprox(16.0, FalconFpr.fpr_sqr(d2l(4.0)), 0L, "4^2=16")
  }

  @Test
  fun `fpr_sqr of zero is zero`() {
    assertEquals(0L, FalconFpr.fpr_sqr(0L), "0^2 should be 0")
  }

  // === fpr_div ===

  @Test
  @Tag("critical-path")
  fun `fpr_div performs IEEE 754 division`() {
    assertFprApprox(3.0, FalconFpr.fpr_div(d2l(9.0), d2l(3.0)), 1L, "9/3=3")
    assertFprApprox(2.0, FalconFpr.fpr_div(d2l(6.0), d2l(3.0)), 1L, "6/3=2")
    assertFprApprox(0.5, FalconFpr.fpr_div(d2l(1.0), d2l(2.0)), 1L, "1/2=0.5")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_div handles negative operands`() {
    assertFprApprox(-3.0, FalconFpr.fpr_div(d2l(-9.0), d2l(3.0)), 1L, "-9/3=-3")
    assertFprApprox(3.0, FalconFpr.fpr_div(d2l(-9.0), d2l(-3.0)), 1L, "-9/-3=3")
  }

  @Test
  fun `fpr_div of zero numerator is zero`() {
    val result = FalconFpr.fpr_div(d2l(0.0), d2l(5.0))
    assertEquals(0L, result, "0/5 should be 0")
  }

  // === fpr_inv ===

  @Test
  @Tag("critical-path")
  fun `fpr_inv computes reciprocal`() {
    assertFprApprox(0.5, FalconFpr.fpr_inv(d2l(2.0)), 1L, "1/2=0.5")
    assertFprApprox(0.25, FalconFpr.fpr_inv(d2l(4.0)), 1L, "1/4=0.25")
    assertFprApprox(0.1, FalconFpr.fpr_inv(d2l(10.0)), 1L, "1/10=0.1")
  }

  // === fpr_sqrt ===

  @Test
  @Tag("critical-path")
  fun `fpr_sqrt computes square root`() {
    assertFprApprox(2.0, FalconFpr.fpr_sqrt(d2l(4.0)), 2L, "sqrt(4)=2")
    assertFprApprox(3.0, FalconFpr.fpr_sqrt(d2l(9.0)), 2L, "sqrt(9)=3")
    assertFprApprox(4.0, FalconFpr.fpr_sqrt(d2l(16.0)), 2L, "sqrt(16)=4")
    assertFprApprox(1.4142135623730951, FalconFpr.fpr_sqrt(d2l(2.0)), 5L, "sqrt(2)")
  }

  @Test
  fun `fpr_sqrt of zero is zero`() {
    val result = FalconFpr.fpr_sqrt(0L)
    assertEquals(0L, result, "sqrt(0) should be 0")
  }

  // === fpr_lt ===

  @Test
  @Tag("critical-path")
  fun `fpr_lt compares positive values correctly`() {
    assertEquals(1, FalconFpr.fpr_lt(d2l(1.0), d2l(2.0)), "1 < 2 should be true")
    assertEquals(0, FalconFpr.fpr_lt(d2l(2.0), d2l(1.0)), "2 < 1 should be false")
    assertEquals(0, FalconFpr.fpr_lt(d2l(1.0), d2l(1.0)), "1 < 1 should be false")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_lt compares negative values correctly`() {
    assertEquals(1, FalconFpr.fpr_lt(d2l(-2.0), d2l(-1.0)), "-2 < -1 should be true")
    assertEquals(0, FalconFpr.fpr_lt(d2l(-1.0), d2l(-2.0)), "-1 < -2 should be false")
  }

  @Test
  @Tag("critical-path")
  fun `fpr_lt compares mixed signs`() {
    assertEquals(1, FalconFpr.fpr_lt(d2l(-1.0), d2l(1.0)), "-1 < 1 should be true")
    assertEquals(0, FalconFpr.fpr_lt(d2l(1.0), d2l(-1.0)), "1 < -1 should be false")
    assertEquals(0, FalconFpr.fpr_lt(d2l(-1.0), d2l(-1.0)), "-1 < -1 should be false")
    assertEquals(0, FalconFpr.fpr_lt(d2l(1.0), d2l(1.0)), "1 < 1 should be false")
  }

  // === fpr_expm_p63 ===
  // Note: fpr_expm_p63 uses fpr_mul(x, fpr_ptwo63) which computes x * 2^63.
  // When |ccs| >= 1.0, the product exceeds 2^63 and fpr_trunc returns 0
  // (the value overflows int64_t). Use ccs < 1.0 to exercise the full path.

  @Test
  @Tag("critical-path")
  fun `fpr_expm_p63 executes without error`() {
    val x = FalconFpr.fpr_of(0L)
    val ccs = FalconFpr.fpr_half(FalconFpr.fpr_of(1L))
    val result = FalconFpr.fpr_expm_p63(x, ccs)
    assertTrue(result != 0L, "fpr_expm_p63 should return non-zero for non-zero ccs")
  }

  @Test
  fun `fpr_expm_p63 produces reasonable results for small inputs`() {
    val x = d2l(0.1)
    val ccs = d2l(0.5)
    val result = FalconFpr.fpr_expm_p63(x, ccs)
    val resultU = result.toULong()
    assertTrue(
        resultU > 0UL,
        "fpr_expm_p63(0.1, 0.5) should return non-zero, got ${resultU}",
    )
  }

  // === Integration ===

  @Test
  @Tag("critical-path")
  fun `round-trip fpr_of then back via longBitsToDouble`() {
    val testValues = listOf(0L, 1L, -1L, 2L, -2L, 3L, -3L, 255L, 256L, 1024L, -1024L)
    for (v in testValues) {
      val fprVal = FalconFpr.fpr_of(v)
      val d = l2d(fprVal)
      assertEquals(v.toDouble(), d, "fpr_of($v) should equal ${v.toDouble()}")
    }
  }
}

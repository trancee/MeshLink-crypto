/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 NTT engine (FIPS 203 §6.2, Algorithms 5–7).
 *
 * Pure-Kotlin implementation of the negacyclic Number-Theoretic Transform
 * over Z_q with q = 3329, R = 2^16 (Montgomery base), and 128 roots of
 * unity in standard (non-Montgomery) form. The zetas table matches the
 * pq-crystals/kyber ref/ntt.c `zetas` array exactly.
 *
 * All reduction paths are branch-free on secret data (ADR-0003):
 * - montgomeryReduce uses 32-bit word arithmetic with a truncated 16-bit
 *   quotient, matching ref/reduce.c.
 * - barrettReduce uses a precomputed multiplier, matching ref/reduce.c.
 * - ntt / invnttTomont use the standard CTC / GS butterfly with no
 *   conditional branches on secret polynomial coefficients.
 *
 * Key difference from ML-DSA (MLDSANtt.kt): Kyber uses 16-bit Montgomery
 * arithmetic (R = 2^16, QINV = -3327, MONT = -1044) with *raw* zetas in the
 * forward transform, while ML-DSA uses 32-bit arithmetic (R = 2^32) with
 * zetas pre-multiplied by R (Montgomery form). The Kyber `fqmul` helper
 * folds the Montgomery division into each butterfly step.
 *
 * References:
 *   - FIPS 203 §6.2 (NTT for ML-KEM)
 *   - pq-crystals/kyber ref/ntt.c, ref/reduce.c
 */
package ch.trancee.meshlink.crypto

/**
 * ML-KEM-512 NTT engine: forward NTT, inverse NTT, Montgomery/Barrett reduction, and constant-time
 * compare/move helpers.
 *
 * The `@Secret` annotation on NTT functions lets the `:crypto-detekt-rules` `ConstantTimeRule`
 * reject any data-dependent branching on secret polynomial coefficients (ADR-0003).
 */
internal object MLKEMNtt {

  /** Field modulus Q = 3329 (FIPS 203 §6.1). */
  const val Q: Int = MLKEM_Q

  /** Q^{-1} mod 2^16 = -3327 (used by Montgomery reduction with R = 2^16). */
  private const val QINV: Int = MLKEM_QINV

  /** R = 2^16 mod Q = -1044 (signed; used to enter/leave Montgomery domain). */
  internal const val MONT: Int = MLKEM_MONT

  /** Normalization factor after inverse NTT: f = 1441 (ref/ntt.c comment: "mont^2/128"). */
  private const val NTT_F: Int = MLKEM_NTT_F

  /** 2^32 mod Q = 1353 (used by polyTomont to enter Montgomery domain). */
  internal const val MONT32: Int = 1353

  /** Polynomial degree N = 256. */
  const val N: Int = MLKEM_N

  /**
   * 128 roots of unity matching pq-crystals/kyber ref/ntt.c `zetas[128]` (no leading zero). Forward
   * NTT starts at index 1; inverse NTT starts at index 127.
   */
  internal val zetas: ShortArray =
      shortArrayOf(
          -1044,
          -758,
          -359,
          -1517,
          1493,
          1422,
          287,
          202,
          -171,
          622,
          1577,
          182,
          962,
          -1202,
          -1474,
          1468,
          573,
          -1325,
          264,
          383,
          -829,
          1458,
          -1602,
          -130,
          -681,
          1017,
          732,
          608,
          -1542,
          411,
          -205,
          -1571,
          1223,
          652,
          -552,
          1015,
          -1293,
          1491,
          -282,
          -1544,
          516,
          -8,
          -320,
          -666,
          -1618,
          -1162,
          126,
          1469,
          -853,
          -90,
          -271,
          830,
          107,
          -1421,
          -247,
          -951,
          -398,
          961,
          -1508,
          -725,
          448,
          -1065,
          677,
          -1275,
          -1103,
          430,
          555,
          843,
          -1251,
          871,
          1550,
          105,
          422,
          587,
          177,
          -235,
          -291,
          -460,
          1574,
          1653,
          -246,
          778,
          1159,
          -147,
          -777,
          1483,
          -602,
          1119,
          -1590,
          644,
          -872,
          349,
          418,
          329,
          -156,
          -75,
          817,
          1097,
          603,
          610,
          1322,
          -1285,
          -1465,
          384,
          -1215,
          -136,
          1218,
          -1335,
          -874,
          220,
          -1187,
          -1659,
          -1185,
          -1530,
          -1278,
          794,
          -1510,
          -854,
          -870,
          478,
          -108,
          -308,
          996,
          991,
          958,
          -1460,
          1522,
          1628,
      )

  // ------------------------------------------------------------------
  // Reduction (FIPS 203, ref/reduce.c)
  // ------------------------------------------------------------------

  /**
   * Montgomery reduction (FIPS 203, ref/reduce.c `montgomeryReduce`).
   *
   * Given a 32-bit integer [a], returns a 16-bit integer congruent to `a · R⁻¹ (mod Q)` where R =
   * 2^16, such that the result lies in (-Q, Q).
   *
   * Matches the C reference exactly:
   * ```
   * t = (int16_t)(a * QINV)       // lower 16 bits of a × Q⁻¹ mod 2^16
   * r = (a - t*Q) >> 16           // arithmetic right shift by 16
   * ```
   *
   * @param a input 32-bit integer (product of two 16-bit values)
   * @return 16-bit integer congruent to a · R⁻¹ mod Q, in range (-Q, Q)
   */
  internal fun montgomeryReduce(a: Int): Int {
    val t = (a * QINV).toShort().toInt()
    return ((a - t * Q) shr 16).toShort().toInt()
  }

  /**
   * Barrett reduction (FIPS 203, ref/reduce.c `barrettReduce`).
   *
   * Given a 16-bit integer [a], returns the centered representative in (-Q/2, Q/2].
   *
   * Uses the precomputed multiplier v = 20159 = ⌊(2^26 + Q/2) / Q⌋:
   * ```
   * t = (v * a + 2^25) >> 26
   * r = a - t * Q
   * ```
   *
   * @param a input coefficient (should be in the range where Barrett is accurate)
   * @return centered representative in (-Q/2, Q/2]
   */
  internal fun barrettReduce(a: Int): Int {
    val v = 20159
    val t = (((v.toLong() * a.toLong()) + (1L shl 25)) shr 26).toInt() * Q
    return a - t
  }

  /**
   * Montgomery multiply: `fqmul(a, b) = montgomeryReduce(a * b)`.
   *
   * Computes a · b · R⁻¹ mod Q where R = 2^16. Used in every NTT butterfly step.
   *
   * @param a first factor (16-bit range)
   * @param b second factor (16-bit range)
   * @return a · b · R⁻¹ mod Q
   */
  internal fun fqmul(a: Int, b: Int): Int = montgomeryReduce(a * b)

  // ------------------------------------------------------------------
  // Forward NTT (FIPS 203, ref/ntt.c `ntt`)
  // ------------------------------------------------------------------

  /**
   * In-place forward NTT (Cooley-Tukey butterfly).
   *
   * Computes the negacyclic NTT of [a] using the 128-entry `zetas` table. The zetas are raw roots
   * of unity (NOT in Montgomery form); each `fqmul` call divides by R = 2^16, so the output
   * coefficients sit in a "divided by R" form. The caller is expected to follow with [polyReduce]
   * (via `polyNtt`) to bring coefficients into the centered range.
   *
   * After this call, coefficients are in bitreversed order.
   *
   * @param a coefficient array of length 256; **modified in place**
   */
  internal fun ntt(@Secret a: IntArray) {
    var k = 1
    var len = 128
    while (len >= 2) {
      var start = 0
      while (start < N) {
        val zeta = zetas[k++].toInt()
        var j = start
        while (j < start + len) {
          val t = fqmul(zeta, a[j + len])
          a[j + len] = a[j] - t
          a[j] = a[j] + t
          j++
        }
        start += len shl 1
      }
      len = len shr 1
    }
  }

  // ------------------------------------------------------------------
  // Inverse NTT + Montgomery normalization (FIPS 203, ref/ntt.c `invntt`)
  // ------------------------------------------------------------------

  /**
   * In-place inverse NTT with Montgomery normalization (`invntt_tomont`).
   *
   * Recovers coefficients from the NTT domain back to standard order. The Gentleman-Sande butterfly
   * is used: each step applies `barrettReduce` after the add and `fqmul` (Montgomery multiply by
   * zeta) after the subtract. After the 7 butterfly levels, a final `fqmul(r[j], F)` with F = 1441
   * normalizes the result to the Montgomery domain (coefficients scaled by R = 2^16).
   *
   * @param a coefficient array of length 256; **modified in place**
   */
  internal fun invnttTomont(@Secret a: IntArray) {
    var k = 127
    var len = 2
    while (len <= 128) {
      var start = 0
      while (start < N) {
        val zeta = zetas[k--].toInt()
        var j = start
        while (j < start + len) {
          val t = a[j]
          a[j] = barrettReduce(t + a[j + len])
          a[j + len] = a[j + len] - t
          a[j + len] = fqmul(zeta, a[j + len])
          j++
        }
        start += len shl 1
      }
      len = len shl 1
    }
    // Final Montgomery normalization: multiply each coefficient by F and divide by R.
    for (j in 0 until N) {
      a[j] = fqmul(a[j], NTT_F)
    }
  }

  // ------------------------------------------------------------------
  // Polynomial-level reduction helpers (ref/poly.c)
  // ------------------------------------------------------------------

  /**
   * In-place lazy reduction: applies [barrettReduce] to all 256 coefficients. Maps each coefficient
   * into the centered range (-Q/2, Q/2].
   */
  internal fun polyReduce(a: IntArray) {
    for (i in a.indices) {
      a[i] = barrettReduce(a[i])
    }
  }

  /**
   * Convert coefficients from standard to Montgomery domain (ref/poly.c `poly_tomont`).
   *
   * Computes `montgomeryReduce(coeff * MONT32)` = `coeff * 2^32 / 2^16 mod Q` = `coeff * R mod Q`
   * for each coefficient, placing the polynomial in Montgomery form.
   */
  internal fun polyTomont(a: IntArray) {
    for (i in a.indices) {
      a[i] = montgomeryReduce(a[i] * MONT32)
    }
  }

  /** c = a + b (no modular reduction; caller must reduce later). */
  internal fun polyAdd(c: IntArray, a: IntArray, b: IntArray) {
    for (i in c.indices) {
      c[i] = a[i] + b[i]
    }
  }

  /** c = a − b (no modular reduction; caller must reduce later). */
  internal fun polySub(c: IntArray, a: IntArray, b: IntArray) {
    for (i in c.indices) {
      c[i] = a[i] - b[i]
    }
  }

  /**
   * Degree-2 polynomial multiplication in Z_q[X]/(X^2 - zeta) (ref/ntt.c `basemul`).
   *
   * Computes r = a · b mod (X^2 - zeta) using Montgomery multiplication. Each `fqmul` divides by R
   * = 2^16, so three `fqmul` calls divide by R^3. The result is in a scaled form that is corrected
   * by the subsequent inverse NTT.
   *
   * @param r output array (result written to r[rOff], r[rOff+1])
   * @param rOff offset of the result pair in [r]
   * @param a first factor array
   * @param aOff offset of the factor pair in [a]
   * @param b second factor array
   * @param bOff offset of the factor pair in [b]
   * @param zeta the modulus root (X^2 - zeta)
   */
  internal fun basemul(
      r: IntArray,
      rOff: Int,
      a: IntArray,
      aOff: Int,
      b: IntArray,
      bOff: Int,
      zeta: Int,
  ) {
    var r0 = fqmul(a[aOff + 1], b[bOff + 1])
    r0 = fqmul(r0, zeta)
    r0 += fqmul(a[aOff], b[bOff])
    var r1 = fqmul(a[aOff], b[bOff + 1])
    r1 += fqmul(a[aOff + 1], b[bOff])
    r[rOff] = r0
    r[rOff + 1] = r1
  }
}

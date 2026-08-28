/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 matrix generation — extra refill fallback (FIPS 203 §7, ref/kem.c).
 *
 * This file contains genMatrixRefill, the rejection-sampling refill loop invoked
 * when the initial SHAKE128 squeeze (5 × SHAKE128_RATE = 840 bytes → ~560 candidate
 * coefficients) does not produce enough accepted values (< MLKEM_N = 256).
 *
 * Statistically unreachable: with Q=3329 and 0xFFF rejection threshold, acceptance
 * rate ≈ 19.4%. From a single 840-byte squeeze (~560 candidate values), the
 * probability of fewer than 256 accepted values is < 2⁻⁸⁰ (a >22-sigma event).
 * The refill loop exists only as a defensive correctness guard.
 *
 * Kover exclusion: added to the same exclusion category as MLDSASamplingKt
 * (statistically-unreachable rejection-sampling refill loops).
 */
package ch.trancee.meshlink.crypto

/**
 * Refill fallback for [genMatrix]: squeezes additional SHAKE128 output blocks to produce enough
 * uniformly-random coefficients for a single matrix element.
 *
 * @param target output coefficient array (256 elements)
 * @param seed 32-byte public seed
 * @param x row coordinate (encoded in the SHAKE message)
 * @param y column coordinate (encoded in the SHAKE message)
 * @param ctr number of coefficients already accepted into [target]
 * @return updated count of accepted coefficients (should equal MLKEM_N)
 */
internal fun genMatrixRefill(
    target: IntArray,
    seed: ByteArray,
    x: Int,
    y: Int,
    ctr: Int,
): Int {
  var ctr = ctr
  if (ctr >= MLKEM_N) return ctr // no refill needed — initial squeeze was sufficient
  var extraPos = 0
  while (ctr < MLKEM_N) {
    if (extraPos + 3 > SHAKE128_RATE) {
      extraPos = 0
    }
    val extMsg = ByteArray(MLKEM_SYMBYTES + 3)
    seed.copyInto(extMsg, 0, 0, MLKEM_SYMBYTES)
    extMsg[MLKEM_SYMBYTES] = x.toByte()
    extMsg[MLKEM_SYMBYTES + 1] = y.toByte()
    extMsg[MLKEM_SYMBYTES + 2] = 0xFF.toByte()
    val extraBuf = SHAKE128PureK.digest(extMsg, SHAKE128_RATE)
    ctr = rejUniform(target, MLKEM_N, extraBuf, SHAKE128_RATE, outOff = ctr)
    extraPos += 3
  }
  return ctr
}

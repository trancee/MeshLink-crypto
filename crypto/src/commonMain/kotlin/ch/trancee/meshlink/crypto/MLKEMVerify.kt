/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 constant-time verification and conditional-move (FIPS 203, ref/verify.c).
 *
 * Branch-free primitives for ciphertext/decapsulation validation:
 * - [verify]: compares two byte arrays in constant time via OR-accumulator.
 * - [cmov]: conditionally copies bytes using a bitmask derived from a 0/1 flag.
 *
 * Both functions follow the constant-time discipline of ADR-0003: the execution
 * path and memory access pattern are independent of secret data. The `@Secret`
 * annotation on [cmov] lets the `ConstantTimeRule` detect violations.
 *
 * Reference: pq-crystals/kyber ref/verify.c
 */
package ch.trancee.meshlink.crypto

/**
 * Constant-time byte-array comparison (ref/verify.c `verify`).
 *
 * Returns 0 if [a] and [b] are equal for all [len] bytes, 1 otherwise. Implemented as a bitwise-OR
 * accumulator (no early-exit branch), so timing is independent of the position of the first
 * difference.
 *
 * @param a first byte array
 * @param b second byte array
 * @param len number of bytes to compare
 * @return 0 if equal, 1 if not equal
 */
internal fun verify(a: ByteArray, aOff: Int, b: ByteArray, bOff: Int, len: Int): Int {
  var r = 0
  for (i in 0 until len) {
    // Mask to unsigned 8-bit via and 0xFF before xor so r stays non-negative.
    // The C reference uses uint8_t r; without masking, sign-extended bytes would
    // make r negative, causing -(r.toLong()) to become positive and shr 63 = 0
    // (false "equal" result).
    r = r or ((a[aOff + i].toInt() and 0xFF) xor (b[bOff + i].toInt() and 0xFF))
  }
  // r is in [0, 255] (always non-negative), so -(r.toLong()) is 0 or negative.
  // 0 shr 63 = 0 (equal), negative shr 63 = -1 (not equal).
  return (-(r.toLong()) shr 63).toInt()
}

/**
 * Constant-time conditional byte copy (ref/verify.c `cmov`).
 *
 * If [b] == 1, copies [len] bytes from [x] to [r]. If [b] == 0, [r] is unchanged. The flag [b] must
 * be 0 or 1 (not just any non-zero value); the `@Secret` annotation ensures the `ConstantTimeRule`
 * verifies no data-dependent branching occurs.
 *
 * Uses the bitmask technique: `mask = -b` is 0x00..00 or 0xFF..FF, and `r[i] ^= mask & (r[i] xor
 * x[i])` selects between r[i] and x[i] without branching.
 *
 * @param r output buffer (modified in place)
 * @param rOff offset into [r]
 * @param x source buffer (read-only)
 * @param xOff offset into [x]
 * @param len number of bytes to conditionally copy
 * @param b condition flag: 1 to copy, 0 to leave [r] unchanged
 */
internal fun cmov(
    @Secret r: ByteArray,
    rOff: Int,
    x: ByteArray,
    xOff: Int,
    len: Int,
    b: Int,
) {
  val mask = -(b.toLong() and 1L)
  for (i in 0 until len) {
    val ri = r[rOff + i].toInt()
    val xi = x[xOff + i].toInt()
    r[rOff + i] = ((ri xor (mask.toInt() and (ri xor xi)))).toByte()
  }
}

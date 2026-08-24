/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-44 polynomial bit-packing (FIPS 204 §3.3, Algorithms 5–8).
 *
 * Pure-Kotlin implementation of the bit-packing schemes used in key and
 * signature encoding:
 *
 * - η-pack (Algorithm 5): 3-bit coefficients → 3 bytes per group of 8 (η=2)
 * - z-pack (Algorithm 7): 18-bit coefficients → 9 bytes per group of 4 (Γ₁=2^17)
 * - t1-pack: 10-bit coefficients → 5 bytes per group of 4
 * - t0-pack (Algorithm 6): 13-bit coefficients → 13 bytes per group of 8 (D=13)
 * - w1-pack: 6-bit coefficients → 3 bytes per group of 4 (Γ₂ = (Q−1)/88)
 *
 * The pack/unpack functions mirror the pq-crystals/dilithium ref/poly.c
 * bit-manipulation exactly, using Int arithmetic with explicit masking.
 *
 * References:
 *   - FIPS 204 §3.3 (encoding of polynomials)
 *   - pq-crystals/dilithium ref/poly.c (polyeta_pack, polyt0_pack, etc.)
 */
package ch.trancee.meshlink.crypto

/**
 * Bit-pack polynomial with coefficients in [−η, η] (FIPS 204 Algorithm 5). Packs 8 coefficients
 * into 3 bytes. Stores η − coeffs[i].
 */
internal fun polyEtaPack(r: ByteArray, rOff: Int, a: IntArray) {
  for (i in 0 until 256 / 8) {
    val t0 = MLDSA_ETA - a[8 * i + 0]
    val t1 = MLDSA_ETA - a[8 * i + 1]
    val t2 = MLDSA_ETA - a[8 * i + 2]
    val t3 = MLDSA_ETA - a[8 * i + 3]
    val t4 = MLDSA_ETA - a[8 * i + 4]
    val t5 = MLDSA_ETA - a[8 * i + 5]
    val t6 = MLDSA_ETA - a[8 * i + 6]
    val t7 = MLDSA_ETA - a[8 * i + 7]

    r[rOff + 3 * i + 0] = ((t0 and 0x7) or (t1 shl 3) or (t2 shl 6)).toByte()
    r[rOff + 3 * i + 1] = ((t2 ushr 2) or (t3 shl 1) or (t4 shl 4) or (t5 shl 7)).toByte()
    r[rOff + 3 * i + 2] = ((t5 ushr 1) or (t6 shl 2) or (t7 shl 5)).toByte()
  }
}

/** Unpack polynomial with coefficients in [−η, η] (inverse of [polyEtaPack]). */
internal fun polyEtaUnpack(r: IntArray, a: ByteArray, aOff: Int) {
  for (i in 0 until 256 / 8) {
    r[8 * i + 0] = (a[aOff + 3 * i + 0].toInt() and 0x7)
    r[8 * i + 1] = (a[aOff + 3 * i + 0].toInt() ushr 3 and 0x7)
    r[8 * i + 2] =
        (((a[aOff + 3 * i + 0].toInt() and 0xFF) ushr 6) or (a[aOff + 3 * i + 1].toInt() shl 2)) and
            0x7
    r[8 * i + 3] = (a[aOff + 3 * i + 1].toInt() ushr 1 and 0x7)
    r[8 * i + 4] = (a[aOff + 3 * i + 1].toInt() ushr 4 and 0x7)
    r[8 * i + 5] =
        (((a[aOff + 3 * i + 1].toInt() and 0xFF) ushr 7) or (a[aOff + 3 * i + 2].toInt() shl 1)) and
            0x7
    r[8 * i + 6] = (a[aOff + 3 * i + 2].toInt() ushr 2 and 0x7)
    r[8 * i + 7] = ((a[aOff + 3 * i + 2].toInt() and 0xFF) ushr 5 and 0x7)

    r[8 * i + 0] = MLDSA_ETA - r[8 * i + 0]
    r[8 * i + 1] = MLDSA_ETA - r[8 * i + 1]
    r[8 * i + 2] = MLDSA_ETA - r[8 * i + 2]
    r[8 * i + 3] = MLDSA_ETA - r[8 * i + 3]
    r[8 * i + 4] = MLDSA_ETA - r[8 * i + 4]
    r[8 * i + 5] = MLDSA_ETA - r[8 * i + 5]
    r[8 * i + 6] = MLDSA_ETA - r[8 * i + 6]
    r[8 * i + 7] = MLDSA_ETA - r[8 * i + 7]
  }
}

/**
 * Bit-pack polynomial z with coefficients in [-(Γ₁−1), Γ₁] (FIPS 204 Algorithm 7). Packs 4
 * coefficients into 9 bytes. Stores Γ₁ − coeffs[i].
 */
internal fun polyZPack(r: ByteArray, rOff: Int, a: IntArray) {
  for (i in 0 until 256 / 4) {
    val t0 = MLDSA_GAMMA1 - a[4 * i + 0]
    val t1 = MLDSA_GAMMA1 - a[4 * i + 1]
    val t2 = MLDSA_GAMMA1 - a[4 * i + 2]
    val t3 = MLDSA_GAMMA1 - a[4 * i + 3]

    r[rOff + 9 * i + 0] = (t0 and 0xFF).toByte()
    r[rOff + 9 * i + 1] = ((t0 ushr 8) and 0xFF).toByte()
    r[rOff + 9 * i + 2] = ((t0 ushr 16) or (t1 shl 2)).toByte()
    r[rOff + 9 * i + 3] = ((t1 ushr 6) and 0xFF).toByte()
    r[rOff + 9 * i + 4] = ((t1 ushr 14) or (t2 shl 4)).toByte()
    r[rOff + 9 * i + 5] = ((t2 ushr 4) and 0xFF).toByte()
    r[rOff + 9 * i + 6] = ((t2 ushr 12) or (t3 shl 6)).toByte()
    r[rOff + 9 * i + 7] = ((t3 ushr 2) and 0xFF).toByte()
    r[rOff + 9 * i + 8] = ((t3 ushr 10) and 0xFF).toByte()
  }
}

/** Unpack polynomial z with coefficients in [-(Γ₁−1), Γ₁] (inverse of [polyZPack]). */
internal fun polyZUnpack(r: IntArray, a: ByteArray, aOff: Int) {
  for (i in 0 until 256 / 4) {
    val v0 =
        (a[aOff + 9 * i + 0].toInt() and 0xFF) or
            ((a[aOff + 9 * i + 1].toInt() and 0xFF) shl 8) or
            ((a[aOff + 9 * i + 2].toInt() and 0xFF) shl 16)
    r[4 * i + 0] = (v0 and 0x3FFFF)
    r[4 * i + 0] = MLDSA_GAMMA1 - r[4 * i + 0]

    val v1 =
        ((a[aOff + 9 * i + 2].toInt() and 0xFF) ushr 2) or
            ((a[aOff + 9 * i + 3].toInt() and 0xFF) shl 6) or
            ((a[aOff + 9 * i + 4].toInt() and 0xFF) shl 14)
    r[4 * i + 1] = (v1 and 0x3FFFF)
    r[4 * i + 1] = MLDSA_GAMMA1 - r[4 * i + 1]

    val v2 =
        ((a[aOff + 9 * i + 4].toInt() and 0xFF) ushr 4) or
            ((a[aOff + 9 * i + 5].toInt() and 0xFF) shl 4) or
            ((a[aOff + 9 * i + 6].toInt() and 0xFF) shl 12)
    r[4 * i + 2] = (v2 and 0x3FFFF)
    r[4 * i + 2] = MLDSA_GAMMA1 - r[4 * i + 2]

    val v3 =
        ((a[aOff + 9 * i + 6].toInt() and 0xFF) ushr 6) or
            ((a[aOff + 9 * i + 7].toInt() and 0xFF) shl 2) or
            ((a[aOff + 9 * i + 8].toInt() and 0xFF) shl 10)
    r[4 * i + 3] = (v3 and 0x3FFFF)
    r[4 * i + 3] = MLDSA_GAMMA1 - r[4 * i + 3]
  }
}

/**
 * Bit-pack polynomial t1 with 10-bit coefficients (FIPS 204 §3.3). Packs 4 coefficients into 5
 * bytes. C reference: polyt1_pack (ref/poly.c)
 */
internal fun polyT1Pack(r: ByteArray, rOff: Int, a: IntArray) {
  for (i in 0 until 256 / 4) {
    r[rOff + 5 * i + 0] = (a[4 * i + 0] and 0xFF).toByte()
    r[rOff + 5 * i + 1] = ((a[4 * i + 0] ushr 8) or (a[4 * i + 1] shl 2)).toByte()
    r[rOff + 5 * i + 2] = ((a[4 * i + 1] ushr 6) or (a[4 * i + 2] shl 4)).toByte()
    r[rOff + 5 * i + 3] = ((a[4 * i + 2] ushr 4) or (a[4 * i + 3] shl 6)).toByte()
    r[rOff + 5 * i + 4] = ((a[4 * i + 3] ushr 2) and 0xFF).toByte()
  }
}

/** Unpack polynomial t1 with 10-bit coefficients (inverse of [polyT1Pack]). */
internal fun polyT1Unpack(r: IntArray, a: ByteArray, aOff: Int) {
  for (i in 0 until 256 / 4) {
    r[4 * i + 0] =
        ((a[aOff + 5 * i + 0].toInt() and 0xFF) or
            ((a[aOff + 5 * i + 1].toInt() and 0xFF) shl 8)) and 0x3FF
    r[4 * i + 1] =
        ((a[aOff + 5 * i + 1].toInt() and 0xFF) ushr 2) or
            ((a[aOff + 5 * i + 2].toInt() and 0xFF) shl 6) and
            0x3FF
    r[4 * i + 2] =
        ((a[aOff + 5 * i + 2].toInt() and 0xFF) ushr 4) or
            ((a[aOff + 5 * i + 3].toInt() and 0xFF) shl 4) and
            0x3FF
    r[4 * i + 3] =
        ((a[aOff + 5 * i + 3].toInt() and 0xFF) ushr 6) or
            ((a[aOff + 5 * i + 4].toInt() and 0xFF) shl 2) and
            0x3FF
  }
}

/**
 * Bit-pack polynomial t0 with 13-bit coefficients (FIPS 204 Algorithm 6). Packs 8 coefficients into
 * 13 bytes. Stores 2^(D-1) − coeffs[i].
 */
internal fun polyT0Pack(r: ByteArray, rOff: Int, a: IntArray) {
  val bias = 1 shl (MLDSA_D - 1)
  for (i in 0 until 256 / 8) {
    val t0 = bias - a[8 * i + 0]
    val t1 = bias - a[8 * i + 1]
    val t2 = bias - a[8 * i + 2]
    val t3 = bias - a[8 * i + 3]
    val t4 = bias - a[8 * i + 4]
    val t5 = bias - a[8 * i + 5]
    val t6 = bias - a[8 * i + 6]
    val t7 = bias - a[8 * i + 7]

    r[rOff + 13 * i + 0] = (t0 and 0xFF).toByte()
    r[rOff + 13 * i + 1] = ((t0 ushr 8) or (t1 shl 5)).toByte()
    r[rOff + 13 * i + 2] = (t1 ushr 3).toByte()
    r[rOff + 13 * i + 3] = ((t1 ushr 11) or (t2 shl 2)).toByte()
    r[rOff + 13 * i + 4] = ((t2 ushr 6) or (t3 shl 7)).toByte()
    r[rOff + 13 * i + 5] = (t3 ushr 1).toByte()
    r[rOff + 13 * i + 6] = ((t3 ushr 9) or (t4 shl 4)).toByte()
    r[rOff + 13 * i + 7] = (t4 ushr 4).toByte()
    r[rOff + 13 * i + 8] = ((t4 ushr 12) or (t5 shl 1)).toByte()
    r[rOff + 13 * i + 9] = ((t5 ushr 7) or (t6 shl 6)).toByte()
    r[rOff + 13 * i + 10] = (t6 ushr 2).toByte()
    r[rOff + 13 * i + 11] = ((t6 ushr 10) or (t7 shl 3)).toByte()
    r[rOff + 13 * i + 12] = (t7 ushr 5).toByte()
  }
}

/** Unpack polynomial t0 with 13-bit coefficients (inverse of [polyT0Pack]). */
internal fun polyT0Unpack(r: IntArray, a: ByteArray, aOff: Int) {
  val bias = 1 shl (MLDSA_D - 1)
  for (i in 0 until 256 / 8) {
    r[8 * i + 0] =
        ((a[aOff + 13 * i + 0].toInt() and 0xFF) or
            ((a[aOff + 13 * i + 1].toInt() and 0xFF) shl 8)) and 0x1FFF
    r[8 * i + 1] =
        ((a[aOff + 13 * i + 1].toInt() and 0xFF) ushr 5) or
            ((a[aOff + 13 * i + 2].toInt() and 0xFF) shl 3) or
            ((a[aOff + 13 * i + 3].toInt() and 0xFF) shl 11) and
            0x1FFF
    r[8 * i + 2] =
        ((a[aOff + 13 * i + 3].toInt() and 0xFF) ushr 2) or
            ((a[aOff + 13 * i + 4].toInt() and 0xFF) shl 6) and
            0x1FFF
    r[8 * i + 3] =
        ((a[aOff + 13 * i + 4].toInt() and 0xFF) ushr 7) or
            ((a[aOff + 13 * i + 5].toInt() and 0xFF) shl 1) or
            ((a[aOff + 13 * i + 6].toInt() and 0xFF) shl 9) and
            0x1FFF
    r[8 * i + 4] =
        ((a[aOff + 13 * i + 6].toInt() and 0xFF) ushr 4) or
            ((a[aOff + 13 * i + 7].toInt() and 0xFF) shl 4) or
            ((a[aOff + 13 * i + 8].toInt() and 0xFF) shl 12) and
            0x1FFF
    r[8 * i + 5] =
        ((a[aOff + 13 * i + 8].toInt() and 0xFF) ushr 1) or
            ((a[aOff + 13 * i + 9].toInt() and 0xFF) shl 7) and
            0x1FFF
    r[8 * i + 6] =
        ((a[aOff + 13 * i + 9].toInt() and 0xFF) ushr 6) or
            ((a[aOff + 13 * i + 10].toInt() and 0xFF) shl 2) or
            ((a[aOff + 13 * i + 11].toInt() and 0xFF) shl 10) and
            0x1FFF
    r[8 * i + 7] =
        ((a[aOff + 13 * i + 11].toInt() and 0xFF) ushr 3) or
            ((a[aOff + 13 * i + 12].toInt() and 0xFF) shl 5) and
            0x1FFF

    r[8 * i + 0] = bias - r[8 * i + 0]
    r[8 * i + 1] = bias - r[8 * i + 1]
    r[8 * i + 2] = bias - r[8 * i + 2]
    r[8 * i + 3] = bias - r[8 * i + 3]
    r[8 * i + 4] = bias - r[8 * i + 4]
    r[8 * i + 5] = bias - r[8 * i + 5]
    r[8 * i + 6] = bias - r[8 * i + 6]
    r[8 * i + 7] = bias - r[8 * i + 7]
  }
}

/**
 * Bit-pack polynomial w1 with 6-bit coefficients (FIPS 204 §3.3). Packs 4 coefficients into 3
 * bytes.
 */
internal fun polyW1Pack(r: ByteArray, rOff: Int, a: IntArray) {
  for (i in 0 until 256 / 4) {
    r[rOff + 3 * i + 0] = ((a[4 * i + 0] and 0x3F) or ((a[4 * i + 1] and 0x3F) shl 6)).toByte()
    r[rOff + 3 * i + 1] = ((a[4 * i + 1] ushr 2) or ((a[4 * i + 2] and 0x3F) shl 4)).toByte()
    r[rOff + 3 * i + 2] = ((a[4 * i + 2] ushr 4) or ((a[4 * i + 3] and 0x3F) shl 2)).toByte()
  }
}

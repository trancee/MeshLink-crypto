package ch.trancee.meshlink.crypto

// ---------------------------------------------------------------------------
// Curve25519 field arithmetic (p = 2^255 − 19), radix-2^26 limbs.
// ---------------------------------------------------------------------------

/**
 * Field element of GF(2^255 − 19), stored as ten radix-2^26 limbs.
 *
 * The limb exponents follow DJB's ref10 layout (ADR-0001):
 * ```
 *  limb  exponent  bit-width
 *  h0       0        26
 *  h1      26        25
 *  h2      51        26
 *  h3      77        25
 *  h4     102        26
 *  h5     128        25
 *  h6     153        26
 *  h7     179        25
 *  h8     204        26
 *  h9     230        25
 * ```
 *
 * Each limb is a signed `Long` whose absolute value stays well within 64 bits after any single
 * arithmetic operation, so no explicit overflow check is required — the carry-propagation step
 * normalises back to a canonical representation (ADR-0001 §3).
 *
 * Pure-Kotlin, constant-time, no `BigInteger`, no native provider. All operations are branch-free
 * on secret data: the `@Secret` annotation on [fromBytes] lets the `:crypto-detekt-rules`
 * `ConstantTimeRule` statically reject any data-dependent branch or secret-indexed access in this
 * file (ADR-0003).
 */
@Suppress("unused")
internal class FieldElement
private constructor(
    private val limbs: LongArray,
) {

  companion object {
    /**
     * Decodes 32 little-endian bytes into a normalised field element (ref10 `fe_frombytes`).
     *
     * @param bytes 32-byte little-endian encoding of a field element.
     */
    fun fromBytes(@Secret bytes: ByteArray): FieldElement {
      val h = LongArray(LIMB_COUNT)
      h[0] = load4(bytes, 0)
      h[1] = load3(bytes, 4) shl 6
      h[2] = load3(bytes, 7) shl 5
      h[3] = load3(bytes, 10) shl 3
      h[4] = load3(bytes, 13) shl 2
      h[5] = load4(bytes, 16)
      h[6] = load3(bytes, 20) shl 7
      h[7] = load3(bytes, 23) shl 5
      h[8] = load3(bytes, 26) shl 4
      h[9] = (load3(bytes, 29) and MASK_23) shl 2
      return FieldElement(carryPropagate(h))
    }

    /** The additive identity (0). */
    fun zero(): FieldElement = FieldElement(LongArray(LIMB_COUNT))

    /** The multiplicative identity (1). */
    fun one(): FieldElement {
      val h = LongArray(LIMB_COUNT)
      h[0] = 1L
      return FieldElement(h)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /** Round-to-nearest carry propagation (ref10 `fe_normalize`). Mutates [h] in place. */
    fun carryPropagate(h: LongArray): LongArray {
      var carry: Long
      carry = (h[0] + ROUND_25) shr 26
      h[0] -= carry shl 26
      h[1] += carry
      carry = (h[1] + ROUND_24) shr 25
      h[1] -= carry shl 25
      h[2] += carry
      carry = (h[2] + ROUND_25) shr 26
      h[2] -= carry shl 26
      h[3] += carry
      carry = (h[3] + ROUND_24) shr 25
      h[3] -= carry shl 25
      h[4] += carry
      carry = (h[4] + ROUND_25) shr 26
      h[4] -= carry shl 26
      h[5] += carry
      carry = (h[5] + ROUND_24) shr 25
      h[5] -= carry shl 25
      h[6] += carry
      carry = (h[6] + ROUND_25) shr 26
      h[6] -= carry shl 26
      h[7] += carry
      carry = (h[7] + ROUND_24) shr 25
      h[7] -= carry shl 25
      h[8] += carry
      carry = (h[8] + ROUND_25) shr 26
      h[8] -= carry shl 26
      h[9] += carry
      carry = (h[9] + ROUND_24) shr 25
      h[9] -= carry shl 25
      h[0] += carry * 19L
      carry = (h[0] + ROUND_25) shr 26
      h[0] -= carry shl 26
      h[1] += carry
      return h
    }

    /** Read 4 little-endian bytes at [off]. */
    fun load4(s: ByteArray, off: Int): Long =
        (s[off].toLong() and 0xFFL) or
            ((s[off + 1].toLong() and 0xFFL) shl 8) or
            ((s[off + 2].toLong() and 0xFFL) shl 16) or
            ((s[off + 3].toLong() and 0xFFL) shl 24)

    /** Read 3 little-endian bytes at [off]. */
    fun load3(s: ByteArray, off: Int): Long =
        (s[off].toLong() and 0xFFL) or
            ((s[off + 1].toLong() and 0xFFL) shl 8) or
            ((s[off + 2].toLong() and 0xFFL) shl 16)

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    /** Number of radix-2^26 limbs (ref10). */
    private const val LIMB_COUNT = 10

    /** Number of bytes in a canonical encoding. */
    private const val BYTE_COUNT = 32

    /** 2^23 − 1: mask clearing the sign bit of a 24-bit load. */
    private const val MASK_23 = 0x7FFFFFL

    /** 2^25: rounding offset for 26-bit limbs. */
    private const val ROUND_25 = 1L shl 25

    /** 2^24: rounding offset for 25-bit limbs. */
    private const val ROUND_24 = 1L shl 24
  }

  /**
   * Adds [other] to `this`, returning a new element with unnormalised limbs (ref10 `fe_add`). Call
   * [normalize] before [toBytes] if a canonical representation is required.
   */
  fun add(other: FieldElement): FieldElement {
    val h = LongArray(LIMB_COUNT)
    for (i in 0 until LIMB_COUNT) {
      h[i] = limbs[i] + other.limbs[i]
    }
    return FieldElement(h)
  }

  /**
   * Subtracts [other] from `this`, returning a new element with unnormalised limbs (ref10
   * `fe_sub`).
   */
  fun sub(other: FieldElement): FieldElement {
    val h = LongArray(LIMB_COUNT)
    for (i in 0 until LIMB_COUNT) {
      h[i] = limbs[i] - other.limbs[i]
    }
    return FieldElement(h)
  }

  /**
   * Multiplies `this` by [other] and fully normalises the result (ref10 `fe_mul` + `fe_normalize`).
   */
  fun mul(other: FieldElement): FieldElement {
    val f0 = limbs[0]
    val f1 = limbs[1]
    val f2 = limbs[2]
    val f3 = limbs[3]
    val f4 = limbs[4]
    val f5 = limbs[5]
    val f6 = limbs[6]
    val f7 = limbs[7]
    val f8 = limbs[8]
    val f9 = limbs[9]
    val g0 = other.limbs[0]
    val g1 = other.limbs[1]
    val g2 = other.limbs[2]
    val g3 = other.limbs[3]
    val g4 = other.limbs[4]
    val g5 = other.limbs[5]
    val g6 = other.limbs[6]
    val g7 = other.limbs[7]
    val g8 = other.limbs[8]
    val g9 = other.limbs[9]

    val g1_19 = g1 * 19L
    val g2_19 = g2 * 19L
    val g3_19 = g3 * 19L
    val g4_19 = g4 * 19L
    val g5_19 = g5 * 19L
    val g6_19 = g6 * 19L
    val g7_19 = g7 * 19L
    val g8_19 = g8 * 19L
    val g9_19 = g9 * 19L

    val h0 =
        (f0 * g0 +
            f1 * (g9_19 * 2L) +
            f2 * g8_19 +
            f3 * (g7_19 * 2L) +
            f4 * g6_19 +
            f5 * (g5_19 * 2L) +
            f6 * g4_19 +
            f7 * (g3_19 * 2L) +
            f8 * g2_19 +
            f9 * (g1_19 * 2L))

    val h1 =
        (f0 * g1 +
            f1 * g0 +
            f2 * g9_19 +
            f3 * g8_19 +
            f4 * g7_19 +
            f5 * g6_19 +
            f6 * g5_19 +
            f7 * g4_19 +
            f8 * g3_19 +
            f9 * g2_19)

    val h2 =
        (f0 * g2 +
            f1 * (g1 * 2L) +
            f2 * g0 +
            f3 * (g9_19 * 2L) +
            f4 * g8_19 +
            f5 * (g7_19 * 2L) +
            f6 * g6_19 +
            f7 * (g5_19 * 2L) +
            f8 * g4_19 +
            f9 * (g3_19 * 2L))

    val h3 =
        (f0 * g3 +
            f1 * g2 +
            f2 * g1 +
            f3 * g0 +
            f4 * g9_19 +
            f5 * g8_19 +
            f6 * g7_19 +
            f7 * g6_19 +
            f8 * g5_19 +
            f9 * g4_19)

    val h4 =
        (f0 * g4 +
            f1 * (g3 * 2L) +
            f2 * g2 +
            f3 * (g1 * 2L) +
            f4 * g0 +
            f5 * (g9_19 * 2L) +
            f6 * g8_19 +
            f7 * (g7_19 * 2L) +
            f8 * g6_19 +
            f9 * (g5_19 * 2L))

    val h5 =
        (f0 * g5 +
            f1 * g4 +
            f2 * g3 +
            f3 * g2 +
            f4 * g1 +
            f5 * g0 +
            f6 * g9_19 +
            f7 * g8_19 +
            f8 * g7_19 +
            f9 * g6_19)

    val h6 =
        (f0 * g6 +
            f1 * (g5 * 2L) +
            f2 * g4 +
            f3 * (g3 * 2L) +
            f4 * g2 +
            f5 * (g1 * 2L) +
            f6 * g0 +
            f7 * (g9_19 * 2L) +
            f8 * g8_19 +
            f9 * (g7_19 * 2L))

    val h7 =
        (f0 * g7 +
            f1 * g6 +
            f2 * g5 +
            f3 * g4 +
            f4 * g3 +
            f5 * g2 +
            f6 * g1 +
            f7 * g0 +
            f8 * g9_19 +
            f9 * g8_19)

    val h8 =
        (f0 * g8 +
            f1 * (g7 * 2L) +
            f2 * g6 +
            f3 * (g5 * 2L) +
            f4 * g4 +
            f5 * (g3 * 2L) +
            f6 * g2 +
            f7 * (g1 * 2L) +
            f8 * g0 +
            f9 * (g9_19 * 2L))

    val h9 =
        (f0 * g9 +
            f1 * g8 +
            f2 * g7 +
            f3 * g6 +
            f4 * g5 +
            f5 * g4 +
            f6 * g3 +
            f7 * g2 +
            f8 * g1 +
            f9 * g0)

    val h = longArrayOf(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9)
    return FieldElement(carryPropagate(h))
  }

  /** Squares `this` (ref10 `fe_sqr` = `fe_mul(a, a)`). */
  fun sqr(): FieldElement = mul(this)

  /**
   * Computes the multiplicative inverse 1/`this` via Fermat's little theorem (ref10 `fe_invert`).
   *
   * p−2 = 2^255 − 21 is a public exponent, so the addition chain is fixed and the operation
   * sequence is independent of the input — the same constant-time discipline as [X25519].
   * Uses the addition chain from ref10 `fe_invert`: 254 squarings + 11 multiplications.
   */
  fun invert(): FieldElement {
    // Exponent = 2^255 − 21 = (2^5)(2^250 − 1) + 11.
    var t0 = this.sqr()          // z^2
    var t1 = t0.sqr()            // z^4
    t1 = t1.sqr()                // z^8
    t1 = this.mul(t1)            // z^9
    t0 = t0.mul(t1)              // z^11 (stash for the end)

    var t2 = t0.sqr()            // z^22
    t1 = t1.mul(t2)              // z^31 = z^(2^5 − 1)
    t2 = t1.sqr()                // z^62
    repeat(4) { t2 = t2.sqr() }  // z^(31·2^5) = z^992
    t1 = t2.mul(t1)              // z^1023 = z^(2^10 − 1)
    t2 = t1.sqr()                // z^2046
    repeat(9) { t2 = t2.sqr() }  // z^(2^20 − 1)
    t2 = t2.mul(t1)
    var t3 = t2.sqr()
    repeat(19) { t3 = t3.sqr() } // z^(2^40 − 1)
    t2 = t3.mul(t2)
    repeat(10) { t2 = t2.sqr() } // z^((2^40−1)·2^10)
    t1 = t2.mul(t1)              // z^(2^50 − 1)
    t2 = t1.sqr()
    repeat(49) { t2 = t2.sqr() } // z^(2^100 − 1)
    t2 = t2.mul(t1)
    t3 = t2.sqr()
    repeat(99) { t3 = t3.sqr() } // z^(2^200 − 1)
    t2 = t3.mul(t2)
    t2 = t2.sqr()                 // z^(2^201 − 2)
    repeat(49) { t2 = t2.sqr() }  // z^(2^250 − 2^50)
    t1 = t2.mul(t1)               // z^(2^250 − 1)
    t1 = t1.sqr()
    repeat(4) { t1 = t1.sqr() }  // z^(2^255 − 32)
    return t1.mul(t0)            // z^(2^255 − 21) = z^(p−2)
  }

  /**
   * Conditionally swaps limbs between `this` and [other] in constant time (ref10 `fe_cswap`). When
   * [bit] is 1 the two elements are swapped; when 0 they are left unchanged. Uses the XOR-mask
   * idiom — no data-dependent branch (ADR-0003).
   */
  fun cswap(other: FieldElement, bit: Int) {
    val mask = -bit.toLong()
    for (i in 0 until LIMB_COUNT) {
      val diff = limbs[i] xor other.limbs[i]
      limbs[i] = limbs[i] xor (diff and mask)
      other.limbs[i] = other.limbs[i] xor (diff and mask)
    }
  }

  /**
   * Returns a new element with limbs fully carry-propagated so that [toBytes] is canonical (ref10
   * `fe_normalize`).
   */
  fun normalize(): FieldElement {
    val h = limbs.copyOf()
    return FieldElement(carryPropagate(h))
  }

  /**
   * Serialises to 32 little-endian bytes (ref10 `fe_tobytes`). After final reduction every limb is
   * in `[0, 2^width)`, so `shr` (arithmetic right shift) behaves as logical shift and matches
   * Python `>>` semantics.
   */
  fun toBytes(): ByteArray {
    var h0 = limbs[0]
    var h1 = limbs[1]
    var h2 = limbs[2]
    var h3 = limbs[3]
    var h4 = limbs[4]
    var h5 = limbs[5]
    var h6 = limbs[6]
    var h7 = limbs[7]
    var h8 = limbs[8]
    var h9 = limbs[9]

    // Final reduction — fold h9 into the [−q·p, h9] range.
    var q = (h9 * 19L + (1L shl 24)) shr 25
    q = (h0 + q) shr 26
    q = (h1 + q) shr 25
    q = (h2 + q) shr 26
    q = (h3 + q) shr 25
    q = (h4 + q) shr 26
    q = (h5 + q) shr 25
    q = (h6 + q) shr 26
    q = (h7 + q) shr 25
    q = (h8 + q) shr 26
    q = (h9 + q) shr 25

    h0 += q * 19L

    // Carry propagation (without rounding offset).
    var carry = h0 shr 26
    h0 -= carry shl 26
    h1 += carry
    carry = h1 shr 25
    h1 -= carry shl 25
    h2 += carry
    carry = h2 shr 26
    h2 -= carry shl 26
    h3 += carry
    carry = h3 shr 25
    h3 -= carry shl 25
    h4 += carry
    carry = h4 shr 26
    h4 -= carry shl 26
    h5 += carry
    carry = h5 shr 25
    h5 -= carry shl 25
    h6 += carry
    carry = h6 shr 26
    h6 -= carry shl 26
    h7 += carry
    carry = h7 shr 25
    h7 -= carry shl 25
    h8 += carry
    carry = h8 shr 26
    h8 -= carry shl 26
    h9 += carry
    carry = h9 shr 25
    h9 -= carry shl 25

    // Pack into 32 little-endian bytes.
    val result = ByteArray(BYTE_COUNT)
    result[0] = (h0 and 0xFFL).toByte()
    result[1] = ((h0 shr 8) and 0xFFL).toByte()
    result[2] = ((h0 shr 16) and 0xFFL).toByte()
    result[3] = ((h0 shr 24 or (h1 shl 2)) and 0xFFL).toByte()
    result[4] = ((h1 shr 6) and 0xFFL).toByte()
    result[5] = ((h1 shr 14) and 0xFFL).toByte()
    result[6] = ((h1 shr 22 or (h2 shl 3)) and 0xFFL).toByte()
    result[7] = ((h2 shr 5) and 0xFFL).toByte()
    result[8] = ((h2 shr 13) and 0xFFL).toByte()
    result[9] = ((h2 shr 21 or (h3 shl 5)) and 0xFFL).toByte()
    result[10] = ((h3 shr 3) and 0xFFL).toByte()
    result[11] = ((h3 shr 11) and 0xFFL).toByte()
    result[12] = ((h3 shr 19 or (h4 shl 6)) and 0xFFL).toByte()
    result[13] = ((h4 shr 2) and 0xFFL).toByte()
    result[14] = ((h4 shr 10) and 0xFFL).toByte()
    result[15] = ((h4 shr 18) and 0xFFL).toByte()
    result[16] = (h5 and 0xFFL).toByte()
    result[17] = ((h5 shr 8) and 0xFFL).toByte()
    result[18] = ((h5 shr 16) and 0xFFL).toByte()
    result[19] = ((h5 shr 24 or (h6 shl 1)) and 0xFFL).toByte()
    result[20] = ((h6 shr 7) and 0xFFL).toByte()
    result[21] = ((h6 shr 15) and 0xFFL).toByte()
    result[22] = ((h6 shr 23 or (h7 shl 3)) and 0xFFL).toByte()
    result[23] = ((h7 shr 5) and 0xFFL).toByte()
    result[24] = ((h7 shr 13) and 0xFFL).toByte()
    result[25] = ((h7 shr 21 or (h8 shl 4)) and 0xFFL).toByte()
    result[26] = ((h8 shr 4) and 0xFFL).toByte()
    result[27] = ((h8 shr 12) and 0xFFL).toByte()
    result[28] = ((h8 shr 20 or (h9 shl 6)) and 0xFFL).toByte()
    result[29] = ((h9 shr 2) and 0xFFL).toByte()
    result[30] = ((h9 shr 10) and 0xFFL).toByte()
    result[31] = ((h9 shr 18) and 0xFFL).toByte()
    return result
  }
}

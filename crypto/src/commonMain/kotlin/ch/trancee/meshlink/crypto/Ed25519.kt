package ch.trancee.meshlink.crypto

// ---------------------------------------------------------------------------
// Ed25519 signatures (RFC 8032 §5.1).
//
// Ported from Tink's Ed25519.java (ref10). Pure-Kotlin, no BigInteger.
// Scalar arithmetic uses 21-bit limbs. Point arithmetic uses extended
// projective coordinates (X:Y:Z:T, XY=ZT).
//
// Constant-time discipline (ADR-0003):
// - sign()'s secretKey is @Secret; ConstantTimeRule bans if/when on it.
// - Scalar mult uses double-and-add-always with FieldElement.cswap.
// - Point decoding (pointFromBytes) is var-time but only consumes public data.
// ---------------------------------------------------------------------------

internal object Ed25519 {

  // ── Constants (32-byte LE) ────────────────────────────────────────────────

  private val GROUP_ORDER: ByteArray =
      hexToBytes("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")

  private val D_BYTES: ByteArray =
      hexToBytes("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352")

  private val D2_BYTES: ByteArray =
      hexToBytes("59f1b226949bd6eb56b183829a14e00030d1f3eef2808e19e7fcdf56dcd90624")

  private val SQRTM1_BYTES: ByteArray =
      hexToBytes("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b")

  private val BASE_POINT_BYTES: ByteArray =
      hexToBytes("5866666666666666666666666666666666666666666666666666666666666666")

  /** 21-bit signed limbs of −k where k = L − 2^252. */
  private val R = longArrayOf(666643L, 470296L, 654183L, -997805L, 136657L, -683901L)

  private const val MASK_21 = 0x1FFFFFL
  private const val ROUND_21 = 1L shl 20

  // Decoded constants
  private val D: FieldElement by lazy { FieldElement.fromBytes(D_BYTES) }
  private val D2: FieldElement by lazy { FieldElement.fromBytes(D2_BYTES) }
  private val SQRTM1: FieldElement by lazy { FieldElement.fromBytes(SQRTM1_BYTES) }
  private val B: Point by lazy { pointFromBytes(BASE_POINT_BYTES)!! }
  private val B_CACHED: CachedPoint by lazy { B.toCached() }

  // ── Helpers ──────────────────────────────────────────────────────────────

  private fun hexToBytes(hex: String): ByteArray =
      ByteArray(hex.length / 2) { i ->
        val hi = hex[i * 2].digitToInt(16)
        val lo = hex[i * 2 + 1].digitToInt(16)
        (hi shl 4 or lo).toByte()
      }

  private fun load3(s: ByteArray, off: Int): Long =
      (s[off].toLong() and 0xFFL) or
          ((s[off + 1].toLong() and 0xFFL) shl 8) or
          ((s[off + 2].toLong() and 0xFFL) shl 16)

  private fun load4(s: ByteArray, off: Int): Long =
      load3(s, off) or ((s[off + 3].toLong() and 0xFFL) shl 24)

  private fun byteArrayEqual(a: ByteArray, b: ByteArray): Boolean {
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
  }

  private fun serializeScalar(
      s0: Long,
      s1: Long,
      s2: Long,
      s3: Long,
      s4: Long,
      s5: Long,
      s6: Long,
      s7: Long,
      s8: Long,
      s9: Long,
      s10: Long,
      s11: Long,
  ): ByteArray {
    val out = ByteArray(32)
    out[0] = s0.toByte()
    out[1] = (s0 ushr 8).toByte()
    out[2] = (s0 ushr 16 or (s1 shl 5)).toByte()
    out[3] = (s1 ushr 3).toByte()
    out[4] = (s1 ushr 11).toByte()
    out[5] = (s1 ushr 19 or (s2 shl 2)).toByte()
    out[6] = (s2 ushr 6).toByte()
    out[7] = (s2 ushr 14 or (s3 shl 7)).toByte()
    out[8] = (s3 ushr 1).toByte()
    out[9] = (s3 ushr 9).toByte()
    out[10] = (s3 ushr 17 or (s4 shl 4)).toByte()
    out[11] = (s4 ushr 4).toByte()
    out[12] = (s4 ushr 12).toByte()
    out[13] = (s4 ushr 20 or (s5 shl 1)).toByte()
    out[14] = (s5 ushr 7).toByte()
    out[15] = (s5 ushr 15 or (s6 shl 6)).toByte()
    out[16] = (s6 ushr 2).toByte()
    out[17] = (s6 ushr 10).toByte()
    out[18] = (s6 ushr 18 or (s7 shl 3)).toByte()
    out[19] = (s7 ushr 5).toByte()
    out[20] = (s7 ushr 13).toByte()
    out[21] = s8.toByte()
    out[22] = (s8 ushr 8).toByte()
    out[23] = (s8 ushr 16 or (s9 shl 5)).toByte()
    out[24] = (s9 ushr 3).toByte()
    out[25] = (s9 ushr 11).toByte()
    out[26] = (s9 ushr 19 or (s10 shl 2)).toByte()
    out[27] = (s10 ushr 6).toByte()
    out[28] = (s10 ushr 14 or (s11 shl 7)).toByte()
    out[29] = (s11 ushr 1).toByte()
    out[30] = (s11 ushr 9).toByte()
    out[31] = (s11 ushr 17).toByte()
    return out
  }

  // ── Scalar reduction (ref10 sc_reduce, 21-bit limbs) ─────────────────────

  fun scReduce(s: ByteArray): ByteArray {
    var s0 = MASK_21 and load3(s, 0)
    var s1 = MASK_21 and (load4(s, 2) ushr 5)
    var s2 = MASK_21 and (load3(s, 5) ushr 2)
    var s3 = MASK_21 and (load4(s, 7) ushr 7)
    var s4 = MASK_21 and (load4(s, 10) ushr 4)
    var s5 = MASK_21 and (load3(s, 13) ushr 1)
    var s6 = MASK_21 and (load4(s, 15) ushr 6)
    var s7 = MASK_21 and (load3(s, 18) ushr 3)
    var s8 = MASK_21 and load3(s, 21)
    var s9 = MASK_21 and (load4(s, 23) ushr 5)
    var s10 = MASK_21 and (load3(s, 26) ushr 2)
    var s11 = MASK_21 and (load4(s, 28) ushr 7)
    var s12 = MASK_21 and (load4(s, 31) ushr 4)
    var s13 = MASK_21 and (load3(s, 34) ushr 1)
    var s14 = MASK_21 and (load4(s, 36) ushr 6)
    var s15 = MASK_21 and (load3(s, 39) ushr 3)
    var s16 = MASK_21 and load3(s, 42)
    var s17 = MASK_21 and (load4(s, 44) ushr 5)
    var s18 = MASK_21 and (load3(s, 47) ushr 2)
    var s19 = MASK_21 and (load4(s, 49) ushr 7)
    var s20 = MASK_21 and (load4(s, 52) ushr 4)
    var s21 = MASK_21 and (load3(s, 55) ushr 1)
    var s22 = MASK_21 and (load4(s, 57) ushr 6)
    var s23 = load4(s, 60) ushr 3

    // Phase 1: fold s23..s18 → s11..s6
    s11 += s23 * R[0]
    s12 += s23 * R[1]
    s13 += s23 * R[2]
    s14 += s23 * R[3]
    s15 += s23 * R[4]
    s16 += s23 * R[5]
    s10 += s22 * R[0]
    s11 += s22 * R[1]
    s12 += s22 * R[2]
    s13 += s22 * R[3]
    s14 += s22 * R[4]
    s15 += s22 * R[5]
    s9 += s21 * R[0]
    s10 += s21 * R[1]
    s11 += s21 * R[2]
    s12 += s21 * R[3]
    s13 += s21 * R[4]
    s14 += s21 * R[5]
    s8 += s20 * R[0]
    s9 += s20 * R[1]
    s10 += s20 * R[2]
    s11 += s20 * R[3]
    s12 += s20 * R[4]
    s13 += s20 * R[5]
    s7 += s19 * R[0]
    s8 += s19 * R[1]
    s9 += s19 * R[2]
    s10 += s19 * R[3]
    s11 += s19 * R[4]
    s12 += s19 * R[5]
    s6 += s18 * R[0]
    s7 += s18 * R[1]
    s8 += s18 * R[2]
    s9 += s18 * R[3]
    s10 += s18 * R[4]
    s11 += s18 * R[5]

    var carry = (s6 + ROUND_21) shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = (s8 + ROUND_21) shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = (s10 + ROUND_21) shr 21
    s11 += carry
    s10 -= carry shl 21
    carry = (s12 + ROUND_21) shr 21
    s13 += carry
    s12 -= carry shl 21
    carry = (s14 + ROUND_21) shr 21
    s15 += carry
    s14 -= carry shl 21
    carry = (s16 + ROUND_21) shr 21
    s17 += carry
    s16 -= carry shl 21
    carry = (s7 + ROUND_21) shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = (s9 + ROUND_21) shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = (s11 + ROUND_21) shr 21
    s12 += carry
    s11 -= carry shl 21
    carry = (s13 + ROUND_21) shr 21
    s14 += carry
    s13 -= carry shl 21
    carry = (s15 + ROUND_21) shr 21
    s16 += carry
    s15 -= carry shl 21

    // Phase 2: fold s17..s12 → s5..s0
    s5 += s17 * R[0]
    s6 += s17 * R[1]
    s7 += s17 * R[2]
    s8 += s17 * R[3]
    s9 += s17 * R[4]
    s10 += s17 * R[5]
    s4 += s16 * R[0]
    s5 += s16 * R[1]
    s6 += s16 * R[2]
    s7 += s16 * R[3]
    s8 += s16 * R[4]
    s9 += s16 * R[5]
    s3 += s15 * R[0]
    s4 += s15 * R[1]
    s5 += s15 * R[2]
    s6 += s15 * R[3]
    s7 += s15 * R[4]
    s8 += s15 * R[5]
    s2 += s14 * R[0]
    s3 += s14 * R[1]
    s4 += s14 * R[2]
    s5 += s14 * R[3]
    s6 += s14 * R[4]
    s7 += s14 * R[5]
    s1 += s13 * R[0]
    s2 += s13 * R[1]
    s3 += s13 * R[2]
    s4 += s13 * R[3]
    s5 += s13 * R[4]
    s6 += s13 * R[5]
    s0 += s12 * R[0]
    s1 += s12 * R[1]
    s2 += s12 * R[2]
    s3 += s12 * R[3]
    s4 += s12 * R[4]
    s5 += s12 * R[5]
    s12 = 0L

    carry = (s0 + ROUND_21) shr 21
    s1 += carry
    s0 -= carry shl 21
    carry = (s2 + ROUND_21) shr 21
    s3 += carry
    s2 -= carry shl 21
    carry = (s4 + ROUND_21) shr 21
    s5 += carry
    s4 -= carry shl 21
    carry = (s6 + ROUND_21) shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = (s8 + ROUND_21) shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = (s10 + ROUND_21) shr 21
    s11 += carry
    s10 -= carry shl 21
    carry = (s1 + ROUND_21) shr 21
    s2 += carry
    s1 -= carry shl 21
    carry = (s3 + ROUND_21) shr 21
    s4 += carry
    s3 -= carry shl 21
    carry = (s5 + ROUND_21) shr 21
    s6 += carry
    s5 -= carry shl 21
    carry = (s7 + ROUND_21) shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = (s9 + ROUND_21) shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = (s11 + ROUND_21) shr 21
    s12 += carry
    s11 -= carry shl 21

    s0 += s12 * R[0]
    s1 += s12 * R[1]
    s2 += s12 * R[2]
    s3 += s12 * R[3]
    s4 += s12 * R[4]
    s5 += s12 * R[5]
    s12 = 0L

    carry = s0 shr 21
    s1 += carry
    s0 -= carry shl 21
    carry = s1 shr 21
    s2 += carry
    s1 -= carry shl 21
    carry = s2 shr 21
    s3 += carry
    s2 -= carry shl 21
    carry = s3 shr 21
    s4 += carry
    s3 -= carry shl 21
    carry = s4 shr 21
    s5 += carry
    s4 -= carry shl 21
    carry = s5 shr 21
    s6 += carry
    s5 -= carry shl 21
    carry = s6 shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = s7 shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = s8 shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = s9 shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = s10 shr 21
    s11 += carry
    s10 -= carry shl 21
    carry = s11 shr 21
    s12 += carry
    s11 -= carry shl 21

    s0 += s12 * R[0]
    s1 += s12 * R[1]
    s2 += s12 * R[2]
    s3 += s12 * R[3]
    s4 += s12 * R[4]
    s5 += s12 * R[5]

    carry = s0 shr 21
    s1 += carry
    s0 -= carry shl 21
    carry = s1 shr 21
    s2 += carry
    s1 -= carry shl 21
    carry = s2 shr 21
    s3 += carry
    s2 -= carry shl 21
    carry = s3 shr 21
    s4 += carry
    s3 -= carry shl 21
    carry = s4 shr 21
    s5 += carry
    s4 -= carry shl 21
    carry = s5 shr 21
    s6 += carry
    s5 -= carry shl 21
    carry = s6 shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = s7 shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = s8 shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = s9 shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = s10 shr 21
    s11 += carry
    s10 -= carry shl 21

    return serializeScalar(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11)
  }

  // ── Scalar multiplication mod L (ref10 sc_muladd) ────────────────────────

  fun scMulAdd(a: ByteArray, b: ByteArray, c: ByteArray): ByteArray {
    val a0 = MASK_21 and load3(a, 0)
    val a1 = MASK_21 and (load4(a, 2) ushr 5)
    val a2 = MASK_21 and (load3(a, 5) ushr 2)
    val a3 = MASK_21 and (load4(a, 7) ushr 7)
    val a4 = MASK_21 and (load4(a, 10) ushr 4)
    val a5 = MASK_21 and (load3(a, 13) ushr 1)
    val a6 = MASK_21 and (load4(a, 15) ushr 6)
    val a7 = MASK_21 and (load3(a, 18) ushr 3)
    val a8 = MASK_21 and load3(a, 21)
    val a9 = MASK_21 and (load4(a, 23) ushr 5)
    val a10 = MASK_21 and (load3(a, 26) ushr 2)
    val a11 = load4(a, 28) ushr 7

    val b0 = MASK_21 and load3(b, 0)
    val b1 = MASK_21 and (load4(b, 2) ushr 5)
    val b2 = MASK_21 and (load3(b, 5) ushr 2)
    val b3 = MASK_21 and (load4(b, 7) ushr 7)
    val b4 = MASK_21 and (load4(b, 10) ushr 4)
    val b5 = MASK_21 and (load3(b, 13) ushr 1)
    val b6 = MASK_21 and (load4(b, 15) ushr 6)
    val b7 = MASK_21 and (load3(b, 18) ushr 3)
    val b8 = MASK_21 and load3(b, 21)
    val b9 = MASK_21 and (load4(b, 23) ushr 5)
    val b10 = MASK_21 and (load3(b, 26) ushr 2)
    val b11 = load4(b, 28) ushr 7

    val c0 = MASK_21 and load3(c, 0)
    val c1 = MASK_21 and (load4(c, 2) ushr 5)
    val c2 = MASK_21 and (load3(c, 5) ushr 2)
    val c3 = MASK_21 and (load4(c, 7) ushr 7)
    val c4 = MASK_21 and (load4(c, 10) ushr 4)
    val c5 = MASK_21 and (load3(c, 13) ushr 1)
    val c6 = MASK_21 and (load4(c, 15) ushr 6)
    val c7 = MASK_21 and (load3(c, 18) ushr 3)
    val c8 = MASK_21 and load3(c, 21)
    val c9 = MASK_21 and (load4(c, 23) ushr 5)
    val c10 = MASK_21 and (load3(c, 26) ushr 2)
    val c11 = MASK_21 and (load4(c, 28) ushr 7)

    var s0 = c0 + a0 * b0
    var s1 = c1 + a0 * b1 + a1 * b0
    var s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0
    var s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0
    var s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0
    var s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0
    var s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0
    var s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0
    var s8 =
        c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1 + a8 * b0
    var s9 =
        c9 +
            a0 * b9 +
            a1 * b8 +
            a2 * b7 +
            a3 * b6 +
            a4 * b5 +
            a5 * b4 +
            a6 * b3 +
            a7 * b2 +
            a8 * b1 +
            a9 * b0
    var s10 =
        c10 +
            a0 * b10 +
            a1 * b9 +
            a2 * b8 +
            a3 * b7 +
            a4 * b6 +
            a5 * b5 +
            a6 * b4 +
            a7 * b3 +
            a8 * b2 +
            a9 * b1 +
            a10 * b0
    var s11 =
        c11 +
            a0 * b11 +
            a1 * b10 +
            a2 * b9 +
            a3 * b8 +
            a4 * b7 +
            a5 * b6 +
            a6 * b5 +
            a7 * b4 +
            a8 * b3 +
            a9 * b2 +
            a10 * b1 +
            a11 * b0
    var s12 =
        a1 * b11 +
            a2 * b10 +
            a3 * b9 +
            a4 * b8 +
            a5 * b7 +
            a6 * b6 +
            a7 * b5 +
            a8 * b4 +
            a9 * b3 +
            a10 * b2 +
            a11 * b1
    var s13 =
        a2 * b11 +
            a3 * b10 +
            a4 * b9 +
            a5 * b8 +
            a6 * b7 +
            a7 * b6 +
            a8 * b5 +
            a9 * b4 +
            a10 * b3 +
            a11 * b2
    var s14 =
        a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3
    var s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4
    var s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5
    var s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6
    var s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7
    var s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8
    var s20 = a9 * b11 + a10 * b10 + a11 * b9
    var s21 = a10 * b11 + a11 * b10
    var s22 = a11 * b11
    var s23 = 0L

    var carry = (s0 + ROUND_21) shr 21
    s1 += carry
    s0 -= carry shl 21
    carry = (s2 + ROUND_21) shr 21
    s3 += carry
    s2 -= carry shl 21
    carry = (s4 + ROUND_21) shr 21
    s5 += carry
    s4 -= carry shl 21
    carry = (s6 + ROUND_21) shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = (s8 + ROUND_21) shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = (s10 + ROUND_21) shr 21
    s11 += carry
    s10 -= carry shl 21
    carry = (s12 + ROUND_21) shr 21
    s13 += carry
    s12 -= carry shl 21
    carry = (s14 + ROUND_21) shr 21
    s15 += carry
    s14 -= carry shl 21
    carry = (s16 + ROUND_21) shr 21
    s17 += carry
    s16 -= carry shl 21
    carry = (s18 + ROUND_21) shr 21
    s19 += carry
    s18 -= carry shl 21
    carry = (s20 + ROUND_21) shr 21
    s21 += carry
    s20 -= carry shl 21
    carry = (s22 + ROUND_21) shr 21
    s23 += carry
    s22 -= carry shl 21

    carry = (s1 + ROUND_21) shr 21
    s2 += carry
    s1 -= carry shl 21
    carry = (s3 + ROUND_21) shr 21
    s4 += carry
    s3 -= carry shl 21
    carry = (s5 + ROUND_21) shr 21
    s6 += carry
    s5 -= carry shl 21
    carry = (s7 + ROUND_21) shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = (s9 + ROUND_21) shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = (s11 + ROUND_21) shr 21
    s12 += carry
    s11 -= carry shl 21
    carry = (s13 + ROUND_21) shr 21
    s14 += carry
    s13 -= carry shl 21
    carry = (s15 + ROUND_21) shr 21
    s16 += carry
    s15 -= carry shl 21
    carry = (s17 + ROUND_21) shr 21
    s18 += carry
    s17 -= carry shl 21
    carry = (s19 + ROUND_21) shr 21
    s20 += carry
    s19 -= carry shl 21
    carry = (s21 + ROUND_21) shr 21
    s22 += carry
    s21 -= carry shl 21

    s11 += s23 * R[0]
    s12 += s23 * R[1]
    s13 += s23 * R[2]
    s14 += s23 * R[3]
    s15 += s23 * R[4]
    s16 += s23 * R[5]
    s10 += s22 * R[0]
    s11 += s22 * R[1]
    s12 += s22 * R[2]
    s13 += s22 * R[3]
    s14 += s22 * R[4]
    s15 += s22 * R[5]
    s9 += s21 * R[0]
    s10 += s21 * R[1]
    s11 += s21 * R[2]
    s12 += s21 * R[3]
    s13 += s21 * R[4]
    s14 += s21 * R[5]
    s8 += s20 * R[0]
    s9 += s20 * R[1]
    s10 += s20 * R[2]
    s11 += s20 * R[3]
    s12 += s20 * R[4]
    s13 += s20 * R[5]
    s7 += s19 * R[0]
    s8 += s19 * R[1]
    s9 += s19 * R[2]
    s10 += s19 * R[3]
    s11 += s19 * R[4]
    s12 += s19 * R[5]
    s6 += s18 * R[0]
    s7 += s18 * R[1]
    s8 += s18 * R[2]
    s9 += s18 * R[3]
    s10 += s18 * R[4]
    s11 += s18 * R[5]

    carry = (s6 + ROUND_21) shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = (s8 + ROUND_21) shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = (s10 + ROUND_21) shr 21
    s11 += carry
    s10 -= carry shl 21
    carry = (s12 + ROUND_21) shr 21
    s13 += carry
    s12 -= carry shl 21
    carry = (s14 + ROUND_21) shr 21
    s15 += carry
    s14 -= carry shl 21
    carry = (s16 + ROUND_21) shr 21
    s17 += carry
    s16 -= carry shl 21
    carry = (s7 + ROUND_21) shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = (s9 + ROUND_21) shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = (s11 + ROUND_21) shr 21
    s12 += carry
    s11 -= carry shl 21
    carry = (s13 + ROUND_21) shr 21
    s14 += carry
    s13 -= carry shl 21
    carry = (s15 + ROUND_21) shr 21
    s16 += carry
    s15 -= carry shl 21

    s5 += s17 * R[0]
    s6 += s17 * R[1]
    s7 += s17 * R[2]
    s8 += s17 * R[3]
    s9 += s17 * R[4]
    s10 += s17 * R[5]
    s4 += s16 * R[0]
    s5 += s16 * R[1]
    s6 += s16 * R[2]
    s7 += s16 * R[3]
    s8 += s16 * R[4]
    s9 += s16 * R[5]
    s3 += s15 * R[0]
    s4 += s15 * R[1]
    s5 += s15 * R[2]
    s6 += s15 * R[3]
    s7 += s15 * R[4]
    s8 += s15 * R[5]
    s2 += s14 * R[0]
    s3 += s14 * R[1]
    s4 += s14 * R[2]
    s5 += s14 * R[3]
    s6 += s14 * R[4]
    s7 += s14 * R[5]
    s1 += s13 * R[0]
    s2 += s13 * R[1]
    s3 += s13 * R[2]
    s4 += s13 * R[3]
    s5 += s13 * R[4]
    s6 += s13 * R[5]
    s0 += s12 * R[0]
    s1 += s12 * R[1]
    s2 += s12 * R[2]
    s3 += s12 * R[3]
    s4 += s12 * R[4]
    s5 += s12 * R[5]
    s12 = 0L

    carry = (s0 + ROUND_21) shr 21
    s1 += carry
    s0 -= carry shl 21
    carry = (s2 + ROUND_21) shr 21
    s3 += carry
    s2 -= carry shl 21
    carry = (s4 + ROUND_21) shr 21
    s5 += carry
    s4 -= carry shl 21
    carry = (s6 + ROUND_21) shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = (s8 + ROUND_21) shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = (s10 + ROUND_21) shr 21
    s11 += carry
    s10 -= carry shl 21
    carry = (s1 + ROUND_21) shr 21
    s2 += carry
    s1 -= carry shl 21
    carry = (s3 + ROUND_21) shr 21
    s4 += carry
    s3 -= carry shl 21
    carry = (s5 + ROUND_21) shr 21
    s6 += carry
    s5 -= carry shl 21
    carry = (s7 + ROUND_21) shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = (s9 + ROUND_21) shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = (s11 + ROUND_21) shr 21
    s12 += carry
    s11 -= carry shl 21

    s0 += s12 * R[0]
    s1 += s12 * R[1]
    s2 += s12 * R[2]
    s3 += s12 * R[3]
    s4 += s12 * R[4]
    s5 += s12 * R[5]
    s12 = 0L

    carry = s0 shr 21
    s1 += carry
    s0 -= carry shl 21
    carry = s1 shr 21
    s2 += carry
    s1 -= carry shl 21
    carry = s2 shr 21
    s3 += carry
    s2 -= carry shl 21
    carry = s3 shr 21
    s4 += carry
    s3 -= carry shl 21
    carry = s4 shr 21
    s5 += carry
    s4 -= carry shl 21
    carry = s5 shr 21
    s6 += carry
    s5 -= carry shl 21
    carry = s6 shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = s7 shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = s8 shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = s9 shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = s10 shr 21
    s11 += carry
    s10 -= carry shl 21
    carry = s11 shr 21
    s12 += carry
    s11 -= carry shl 21

    s0 += s12 * R[0]
    s1 += s12 * R[1]
    s2 += s12 * R[2]
    s3 += s12 * R[3]
    s4 += s12 * R[4]
    s5 += s12 * R[5]

    carry = s0 shr 21
    s1 += carry
    s0 -= carry shl 21
    carry = s1 shr 21
    s2 += carry
    s1 -= carry shl 21
    carry = s2 shr 21
    s3 += carry
    s2 -= carry shl 21
    carry = s3 shr 21
    s4 += carry
    s3 -= carry shl 21
    carry = s4 shr 21
    s5 += carry
    s4 -= carry shl 21
    carry = s5 shr 21
    s6 += carry
    s5 -= carry shl 21
    carry = s6 shr 21
    s7 += carry
    s6 -= carry shl 21
    carry = s7 shr 21
    s8 += carry
    s7 -= carry shl 21
    carry = s8 shr 21
    s9 += carry
    s8 -= carry shl 21
    carry = s9 shr 21
    s10 += carry
    s9 -= carry shl 21
    carry = s10 shr 21
    s11 += carry
    s10 -= carry shl 21

    return serializeScalar(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11)
  }

  /** @return true iff [s] (32 LE bytes) is strictly less than the group order L. */
  fun isSmallerThanGroupOrder(s: ByteArray): Boolean {
    for (j in 31 downTo 0) {
      val a = s[j].toInt() and 0xFF
      val b = GROUP_ORDER[j].toInt() and 0xFF
      if (a != b) return a < b
    }
    return false
  }

  // ── Exponentiation ──

  /** Computes z^(2^252−3) via the ref10 pow2252m3 addition chain. */
  private fun pow2252m3(z: FieldElement): FieldElement {
    var t0 = z.sqr() // z^2
    var t1 = t0.sqr()
    t1 = t1.sqr() // z^8
    t1 = z.mul(t1) // z^9
    t0 = t0.mul(t1) // z^11
    t0 = t0.sqr() // z^22
    t0 = t1.mul(t0) // z^31  (z_5_0 = z9 * z22)
    t1 = t0.sqr() // z^62
    repeat(4) { t1 = t1.sqr() } // z^(31*32) = z^992 (z_10_5)
    t0 = t1.mul(t0) // z^1023 (z_10_0)
    t1 = t0.sqr() // z^2046
    repeat(9) { t1 = t1.sqr() } // z^(1023*1024) = z^(2^20-2^10)
    t1 = t1.mul(t0) // z^(2^20-1)
    var t2 = t1.sqr() // z^(2^21-2)
    repeat(19) { t2 = t2.sqr() } // z^(2^40-2^20)
    t1 = t2.mul(t1) // z^(2^40-1)
    t1 = t1.sqr() // z^(2^41-2)
    repeat(9) { t1 = t1.sqr() } // z^(2^50-2^10)
    t0 = t1.mul(t0) // z^(2^50-1) [t0 was z^1023]
    t1 = t0.sqr() // z^(2^51-2)
    repeat(49) { t1 = t1.sqr() } // z^(2^100-2^50)
    t1 = t1.mul(t0) // z^(2^100-1)
    t2 = t1.sqr() // z^(2^101-2)
    repeat(99) { t2 = t2.sqr() } // z^(2^200-2^100)
    t1 = t2.mul(t1) // z^(2^200-1)
    t1 = t1.sqr() // z^(2^201-2)
    repeat(49) { t1 = t1.sqr() } // z^(2^250-2^50)
    t0 = t1.mul(t0) // z^(2^250-1) [t0 was z^(2^50-1)]
    t0 = t0.sqr()
    t0 = t0.sqr() // z^(2^252-4)
    return t0.mul(z) // z^(2^252-3) = z^((p-5)/8)
  }

  // ── Point types ──────────────────────────────────────────────────────────

  /** Extended projective point (X:Y:Z:T), x=X/Z, y=Y/Z, XY=ZT (ref10 ge_p3). */
  private class Point(
      val x: FieldElement,
      val y: FieldElement,
      val z: FieldElement,
      val t: FieldElement,
  ) {

    /** Encodes to 32 LE bytes (ref10 ge_p3_tobytes). */
    fun toBytes(): ByteArray {
      val recip = z.invert()
      val bytes = y.mul(recip).toBytes()
      val xLsb = x.mul(recip).toBytes()[0].toInt() and 1
      bytes[31] = (bytes[31].toInt() xor (xLsb shl 7)).toByte()
      return bytes
    }

    fun toCached(): CachedPoint =
        CachedPoint(
            yPlusX = y.add(x),
            yMinusX = y.sub(x),
            t2d = t.mul(D2),
            z = z,
        )

    /** Double (Hisil §3.3, formula 7, with H→A+B correction). */
    fun double(): Point {
      val xx = x.sqr()
      val yy = y.sqr()
      val b = z.sqr().let { it.add(it) }
      val aa = x.add(y).sqr()
      val y3 = yy.add(xx)
      val z3 = yy.sub(xx)
      val x3 = aa.sub(y3)
      val t3 = b.sub(z3)
      return Point(x3.mul(t3), y3.mul(z3), z3.mul(t3), x3.mul(y3))
    }

    /** Add a cached point (Hisil §3.1). */
    fun add(c: CachedPoint): Point {
      val ypx = y.add(x)
      val ymx = y.sub(x)
      val a = ymx.mul(c.yMinusX) // (Y1-X1)(Y2-X2)
      val b = ypx.mul(c.yPlusX) // (Y1+X1)(Y2+X2)
      val cc = t.mul(c.t2d) // T1*2d*T2
      val d = z.mul(c.z).let { it.add(it) } // 2*Z1*Z2
      val x3 = b.sub(a)
      val y3 = b.add(a) // X3=B-A, Y3=B+A
      val z3 = d.add(cc)
      val t3 = d.sub(cc) // Z3=D+C, T3=D-C
      return Point(x3.mul(t3), y3.mul(z3), z3.mul(t3), x3.mul(y3))
    }

    /** Conditionally swap (ref10 ge_cswap). */
    fun cswap(o: Point, bit: Int) {
      x.cswap(o.x, bit)
      y.cswap(o.y, bit)
      z.cswap(o.z, bit)
      t.cswap(o.t, bit)
    }

    /** Negate: (X,Y,Z,T) → (-X,Y,Z,-T). */
    fun negate(): Point =
        Point(
            x = FieldElement.zero().sub(x),
            y = y,
            z = z,
            t = FieldElement.zero().sub(t),
        )
  }

  private class CachedPoint(
      val yPlusX: FieldElement,
      val yMinusX: FieldElement,
      val t2d: FieldElement,
      val z: FieldElement,
  )

  private fun identityPoint(): Point =
      Point(
          FieldElement.zero(),
          FieldElement.one(),
          FieldElement.one(),
          FieldElement.zero(),
      )

  /** Decodes 32 LE bytes into a point (ref10 ge_frombytes). Returns null if invalid. */
  private fun pointFromBytes(s: ByteArray): Point? {
    val y = FieldElement.fromBytes(s)
    val z = FieldElement.one()
    val y2 = y.mul(y)
    val u = y2.sub(z) // y² - 1
    val v = D.mul(y2).add(z) // d·y² + 1

    val v3 = v.sqr().mul(v) // v³
    var x = v3.sqr().mul(v).mul(u) // u·v^7
    x = pow2252m3(x) // (u·v^7)^((p-5)/8)
    x = x.mul(v3).mul(u) // ·v³·u

    val check = x.sqr().mul(v).sub(u) // v·x² - u
    if (check.toBytes().any { it != 0.toByte() }) {
      x = x.mul(SQRTM1)
    }

    val xBytes = x.toBytes()
    val signBit = (s[31].toInt() and 0xFF) ushr 7
    // x = 0 with sign bit 1 is an invalid encoding
    if (xBytes.all { it == 0.toByte() } && signBit == 1) return null
    if ((xBytes[0].toInt() and 1) != signBit) {
      x = FieldElement.zero().sub(x)
    }

    return Point(x, y, z, x.mul(y))
  }

  // ── Scalar multiplication (double-and-add-always with cswap) ────────────

  private fun scalarBit(scalar: ByteArray, t: Int): Int =
      (scalar[t ushr 3].toInt() ushr (t and 7)) and 1

  private fun scalarMultBase(scalar: ByteArray): Point {
    var q = identityPoint()
    for (t in 254 downTo 0) {
      val bit = scalarBit(scalar, t)
      val q2 = q.double()
      val s = q2.add(B_CACHED)
      q2.cswap(s, bit)
      q = q2
    }
    return q
  }

  private fun scalarMult(scalar: ByteArray, point: Point): Point {
    var q = identityPoint()
    val cached = point.toCached()
    for (t in 254 downTo 0) {
      val bit = scalarBit(scalar, t)
      val q2 = q.double()
      val s = q2.add(cached)
      q2.cswap(s, bit)
      q = q2
    }
    return q
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /** Derives the 32-byte Ed25519 public key from a 32-byte secret key (RFC 8032 §5.1.2). */
  fun publicKeyFromPrivate(secretKey: ByteArray): ByteArray {
    val h = SHA512.digest(secretKey)
    h[0] = (h[0].toInt() and 0xF8).toByte()
    h[31] = (h[31].toInt() and 0x7F).toByte()
    h[31] = (h[31].toInt() or 0x40).toByte()
    return scalarMultBase(h.copyOfRange(0, 32)).toBytes()
  }

  /** Signs [message] with [secretKey], producing a 64-byte Ed25519 signature (RFC 8032 §5.1.5). */
  fun sign(@Secret secretKey: ByteArray, message: ByteArray): ByteArray {
    val h = SHA512.digest(secretKey)
    h[0] = (h[0].toInt() and 0xF8).toByte()
    h[31] = (h[31].toInt() and 0x7F).toByte()
    h[31] = (h[31].toInt() or 0x40).toByte()
    val a = h.copyOfRange(0, 32) // clamped scalar
    val publicKey = scalarMultBase(a).toBytes() // A = a·B

    val hasher = SHA512Hasher()
    hasher.update(h, 32, 32)
    hasher.update(message)
    val r = scReduce(hasher.digest())
    val rB = scalarMultBase(r).toBytes()

    val hasher2 = SHA512Hasher()
    hasher2.update(rB)
    hasher2.update(publicKey)
    hasher2.update(message)
    val hram = scReduce(hasher2.digest())
    val s = scMulAdd(hram, a, r)

    return rB + s
  }

  /**
   * Verifies [signature] on [message] against [publicKey] (RFC 8032 §5.1.6).
   *
   * Returns false for any malformed input — wrong lengths, non-canonical S, or invalid public-key
   * encoding — without throwing.
   */
  fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    if (signature.size != 64) return false
    if (publicKey.size != 32) return false
    val r = signature.copyOfRange(0, 32)
    val s = signature.copyOfRange(32, 64)
    if (!isSmallerThanGroupOrder(s)) return false
    val hasher = SHA512Hasher()
    hasher.update(r)
    hasher.update(publicKey)
    hasher.update(message)
    val h = scReduce(hasher.digest())
    val a = pointFromBytes(publicKey) ?: return false
    val negA = a.negate()
    val sb = scalarMultBase(s)
    val hnegA = scalarMult(h, negA)
    val rPrime = sb.add(hnegA.toCached())
    return byteArrayEqual(rPrime.toBytes(), r)
  }
}

package ch.trancee.meshlink.crypto

/**
 * X25519 key agreement (RFC 7748 §5).
 *
 * Pure-Kotlin, constant-time scalar multiplication on the Curve25519 Montgomery curve, built on the
 * radix-2^26 field engine (ADR-0001). The field engine is [FieldElement]; this object wires the
 * Montgomery ladder and the Fermat inversion on top of it.
 *
 * The computation is:
 * - Clamp the 32-byte scalar (clear bits 0–2 of byte 0, clear bit 7 of byte 31, set bit 6 of
 *   byte 31) so the resulting scalar has the form 2^254 + 8k.
 * - Decode the 32-byte u-coordinate as a field element (x_1).
 * - Run the Montgomery ladder for 255 rounds (bits 254 down to 0), using [FieldElement.cswap] to
 *   avoid data-dependent branches.
 * - Compute z_2^(p−2) via Fermat's little theorem (the addition chain is hard-coded; the exponent
 *   p−2 = 2^255−21 is public, so the operation sequence is fixed and independent of the secret
 *   scalar).
 * - Return x_2 * z_2^(p−2) encoded as 32 little-endian bytes.
 *
 * Constant-time discipline (ADR-0003):
 * - [scalar] and [u] are annotated [Secret]; no data-dependent branch or secret-indexed array
 *   access touches them — the detekt [ConstantTimeRule] statically rejects such patterns.
 * - Scalar bit extraction uses constant-offset indexing (byte index derived from the public loop
 *   counter, not from the secret value).
 * - The Montgomery ladder always performs all 255 iterations with the same sequence of field
 *   operations; only the cswap mask varies.
 * - The inversion addition chain is fixed (public exponent).
 */
internal object X25519PureK {

  /** Curve constant a24 = (486662 − 2) / 4 = 121665 (RFC 7748 §4.1). */
  private val A24: FieldElement =
      FieldElement.fromBytes(
          ByteArray(32) { index ->
            when (index) {
              0 -> 0x41.toByte()
              1 -> 0xDB.toByte()
              2 -> 0x01.toByte()
              else -> 0.toByte()
            }
          }
      )

  /** Returns true if [secret] is the all-zero 32-byte value — a weak X25519 shared secret (RFC 7748 §6.1). */
  internal fun isAllZeroSharedSecret(secret: ByteArray): Boolean =
      secret.size == 32 && secret.all { it == 0.toByte() }

  /**
   * Computes X25519(scalar, u) per RFC 7748 §5 (Montgomery ladder).
   *
   * @param scalar the 32-byte private scalar (little-endian). Must be exactly 32 bytes.
   * @param u the 32-byte u-coordinate (little-endian). Must be exactly 32 bytes.
   * @return the 32-byte shared secret (little-endian).
   */
  fun compute(@Secret scalar: ByteArray, @Secret u: ByteArray): ByteArray {
    require(scalar.size == 32) { "scalar must be 32 bytes" }
    require(u.size == 32) { "u-coordinate must be 32 bytes" }

    // Clamp the scalar (RFC 7748 §5.2, decodeScalar25519).
    val k = clamp(scalar)

    // x_1 = u (decoded as a field element).
    val x1 = FieldElement.fromBytes(u)

    // Montgomery ladder initialisation (RFC 7748 §5).
    //   x_2 = 1, z_2 = 0, x_3 = u, z_3 = 1
    var x2 = FieldElement.one()
    var z2 = FieldElement.zero()
    var x3 = FieldElement.fromBytes(u)
    var z3 = FieldElement.one()
    var swap = 0

    // 255 rounds: t = 254 down to 0 (RFC 7748 §5, bits = 255 for X25519).
    // Bit 254 is always 1 after clamping. Each round performs cswap then the ladder step.
    for (t in 254 downTo 0) {
      val kt = bit(k, t)
      swap = swap xor kt
      x2.cswap(x3, swap)
      z2.cswap(z3, swap)
      swap = kt

      // Ladder step (RFC 7748 §5).
      val a = x2.add(z2)
      val aa = a.sqr()
      val b = x2.sub(z2)
      val bb = b.sqr()
      val e = aa.sub(bb)
      val c = x3.add(z3)
      val d = x3.sub(z3)
      val da = d.mul(a)
      val cb = c.mul(b)
      x3 = da.add(cb).sqr()
      z3 = x1.mul(da.sub(cb).sqr())
      x2 = aa.mul(bb)
      z2 = e.mul(aa.add(A24.mul(e)))
    }

    // Final conditional swap (RFC 7748 §5): swap = k_0 after the last round.
    x2.cswap(x3, swap)
    z2.cswap(z3, swap)

    // Return x_2 * z_2^(p−2) (Fermat's little theorem).
    val inverse = invert(z2)
    val result = x2.mul(inverse).normalize().toBytes()
    // RFC 7748 §6.1: abort if the shared secret is all-zero (u=0 is a low-order point
    // producing the all-zero shared secret). An attacker who supplies u=0 knows the
    // shared secret and can decrypt all session traffic.
    if (result.all { it == 0.toByte() }) {
        throw IllegalArgumentException("X25519 shared secret is all-zero — rejecting low-order point (RFC 7748 §6.1)")
    }
    return result
  }

  /**
   * Clamps the scalar per RFC 7748 §5.2: clears the low 3 bits of byte 0, clears the high bit of
   * byte 31, sets the second-highest bit of byte 31.
   */
  private fun clamp(scalar: ByteArray): ByteArray {
    val k = scalar.copyOf()
    k[0] = (k[0].toInt() and 0xF8).toByte() // clear bottom 3 bits
    k[31] = (k[31].toInt() and 0x7F).toByte() // clear top bit
    k[31] = (k[31].toInt() or 0x40).toByte() // set second-highest bit
    return k
  }

  /**
   * Extracts bit [t] from the little-endian byte array [k].
   *
   * The byte index and bit offset are derived from the public loop counter [t], not from the secret
   * value, so this is constant-time.
   */
  private fun bit(k: ByteArray, t: Int): Int {
    val byteIndex = t ushr 3
    val bitOffset = t and 7
    return (k[byteIndex].toInt() ushr bitOffset) and 1
  }

  /**
   * Computes z^(p−2) mod p where p = 2^255 − 19 (Fermat's little theorem gives z^(p−1) = 1, so
   * z^(p−2) = z^(−1)). The exponent 2^255 − 21 is a public constant, so the addition chain is fixed
   * and the operation sequence is independent of the secret input.
   *
   * Uses the addition chain from DJB's ref10 `fe_invert`: 254 squarings + 11 multiplications.
   */
  private fun invert(z: FieldElement): FieldElement {
    // Compute z^(p-2) = z^(2^255 - 21) using the ref10 fe_invert addition chain.
    // Exponent = (2^5) * (2^250 - 1) + 11 = 2^255 - 32 + 11 = 2^255 - 21.
    // 254 squarings + 11 multiplications.

    // t0 = z^2
    var t0 = z.sqr()

    // t1 = z^8
    var t1 = t0.sqr()
    t1 = t1.sqr()

    // t1 = z^9 = z * z^8
    t1 = z.mul(t1)

    // t0 = z^11 = z^2 * z^9 (stash for the end)
    t0 = t0.mul(t1)

    // t2 = z^22 = t0^2
    var t2 = t0.sqr()

    // t1 = z^31 = z^9 * z^22 = z^(2^5 - 1)
    t1 = t1.mul(t2)

    // t2 = z^(31 * 2^5) = z^992
    t2 = t1.sqr()
    repeat(4) { t2 = t2.sqr() }

    // t1 = z^1023 = z^(2^10 - 1) = t2 * t1
    t1 = t2.mul(t1)

    // t2 = z^(2^20 - 1)
    t2 = t1.sqr()
    repeat(9) { t2 = t2.sqr() }
    t2 = t2.mul(t1)

    // t3 = z^(2^40 - 1)
    var t3 = t2.sqr()
    repeat(19) { t3 = t3.sqr() }
    t2 = t3.mul(t2)

    // t2 = z^((2^40-1) * 2^10)
    repeat(10) { t2 = t2.sqr() }

    // t1 = z^(2^50 - 1) = t2 * t1
    t1 = t2.mul(t1)

    // t2 = z^(2^100 - 1)
    t2 = t1.sqr()
    repeat(49) { t2 = t2.sqr() }
    t2 = t2.mul(t1)

    // t3 = z^(2^200 - 1)
    t3 = t2.sqr()
    repeat(99) { t3 = t3.sqr() }
    t2 = t3.mul(t2)

    // t2 = z^((2^200-1) * 2^50) = z^(2^250 - 2^50)
    t2 = t2.sqr()
    repeat(49) { t2 = t2.sqr() }

    // t1 = z^(2^250 - 1) = t2 * t1
    t1 = t2.mul(t1)

    // t1 = z^((2^250-1) * 2^5) = z^(2^255 - 32)
    t1 = t1.sqr()
    repeat(4) { t1 = t1.sqr() }

    // out = z^(2^255-32) * z^11 = z^(2^255-21) = z^(p-2)
    return t1.mul(t0)
  }
}

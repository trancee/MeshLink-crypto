/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 polynomial operations (FIPS 203 §6.2, ref/poly.c, ref/reduce.c, ref/cbd.c).
 *
 * Pure-Kotlin implementation of per-polynomial arithmetic: compression and
 * serialization (pack/unpack), message encoding/decoding, NTT delegation,
 * Montgomery-domain multiplication, and noise sampling. All reduction paths are
 * branch-free on secret data (ADR-0003).
 *
 * The compression and message-encoding functions use fixed-point integer
 * arithmetic (matching the C reference) instead of floating-point `round()`,
 * ensuring bit-exact compatibility across platforms.
 *
 * Reference: pq-crystals/kyber ref/poly.c, ref/reduce.c, ref/cbd.c
 */
package ch.trancee.meshlink.crypto

// ------------------------------------------------------------------
// Compression (FIPS 203 §6.2, ref/poly.c poly_compress / poly_decompress)
// ------------------------------------------------------------------

/**
 * Compress and serialize a polynomial to 128 bytes (4-bit coefficients).
 *
 * Each coefficient is first reduced to the positive representative [0, Q), then compressed to 4
 * bits via fixed-point rounding: `round(coeff * 16 / Q)`. The 4-bit values are packed 2-per-byte.
 *
 * Fixed-point implementation matches ref/poly.c exactly:
 * ```
 * d0 = (u << 4) + 1665;   // 1665 = Q/2 rounded up
 * d0 *= 80635;            // 80635 ≈ 2^28 / Q
 * d0 >>= 28;              // divide by 2^28
 * ```
 *
 * @param r output byte array (128 bytes, written from [rOff])
 * @param rOff offset in [r] where output begins
 * @param a input polynomial coefficients (256 elements)
 */
internal fun polyCompress(r: ByteArray, rOff: Int, a: IntArray) {
  for (i in 0 until MLKEM_N / 8) {
    val t = IntArray(8)
    for (j in 0 until 8) {
      // Map to positive representative: u += (u >> 31) & Q
      var u = a[8 * i + j]
      u += (u shr 31) and MLKEM_Q
      var d0 = u.toLong() shl 4
      d0 += 1665
      d0 *= 80635
      d0 = d0 shr 28
      t[j] = (d0 and 0xF).toInt()
    }
    r[rOff + 4 * i + 0] = (t[0] or (t[1] shl 4)).toByte()
    r[rOff + 4 * i + 1] = (t[2] or (t[3] shl 4)).toByte()
    r[rOff + 4 * i + 2] = (t[4] or (t[5] shl 4)).toByte()
    r[rOff + 4 * i + 3] = (t[6] or (t[7] shl 4)).toByte()
  }
}

/**
 * De-serialize and decompress a polynomial from 128 bytes (4-bit coefficients).
 *
 * Inverse of [polyCompress]. Each 4-bit value `t` is expanded to `round(t * Q / 16)` via `((t *
 * Q) + 8) >> 4`.
 *
 * @param r output coefficient array (256 elements, filled in place)
 * @param a input byte array
 * @param aOff offset in [a] where compressed data begins
 */
internal fun polyDecompress(r: IntArray, a: ByteArray, aOff: Int) {
  for (i in 0 until MLKEM_N / 2) {
    val b = a[aOff + i].toInt() and 0xFF
    r[2 * i] = ((b and 0x0F) * MLKEM_Q + 8) shr 4
    r[2 * i + 1] = ((b ushr 4) * MLKEM_Q + 8) shr 4
  }
}

// ------------------------------------------------------------------
// Polynomial serialization (ref/poly.c poly_tobytes / poly_frombytes)
// ------------------------------------------------------------------

/**
 * Serialize a polynomial to 384 bytes (12-bit coefficients, 2 per 3 bytes).
 *
 * Each pair of coefficients is reduced to the positive representative [0, Q) and packed into 3
 * bytes, with the middle byte shared between adjacent pairs.
 *
 * @param r output byte array (384 bytes, written from [rOff])
 * @param rOff offset in [r]
 * @param a input polynomial coefficients (256 elements)
 */
internal fun polyTobytes(r: ByteArray, rOff: Int, a: IntArray) {
  for (i in 0 until MLKEM_N / 2) {
    var t0 = a[2 * i]
    t0 += (t0 shr 31) and MLKEM_Q
    var t1 = a[2 * i + 1]
    t1 += (t1 shr 31) and MLKEM_Q
    r[rOff + 3 * i + 0] = t0.toByte()
    r[rOff + 3 * i + 1] = ((t0 ushr 8) or (t1 shl 4)).toByte()
    r[rOff + 3 * i + 2] = (t1 ushr 4).toByte()
  }
}

/**
 * De-serialize a polynomial from 384 bytes (12-bit coefficients).
 *
 * Inverse of [polyTobytes].
 *
 * @param r output coefficient array (256 elements, filled in place)
 * @param a input byte array
 * @param aOff offset in [a]
 */
internal fun polyFrombytes(r: IntArray, a: ByteArray, aOff: Int) {
  for (i in 0 until MLKEM_N / 2) {
    r[2 * i] =
        ((a[aOff + 3 * i].toInt() and 0xFF) or ((a[aOff + 3 * i + 1].toInt() and 0xFF) shl 8)) and
            0xFFF
    r[2 * i + 1] =
        ((a[aOff + 3 * i + 1].toInt() and 0xF0) ushr
            4 or
            ((a[aOff + 3 * i + 2].toInt() and 0xFF) shl 4)) and 0xFFF
  }
}

// ------------------------------------------------------------------
// Message encoding (ref/poly.c poly_frommsg / poly_tomsg)
// ------------------------------------------------------------------

/**
 * Convert a 32-byte message to a polynomial (ref/poly.c `poly_frommsg`).
 *
 * Each bit of [msg] expands to a coefficient: 0 → 0, 1 → (Q+1)/2 = 1665. Uses constant-time
 * conditional assignment to avoid data-dependent branching (ADR-0003).
 *
 * @param r output coefficient array (256 elements, filled in place)
 * @param msg 32-byte message
 */
internal fun polyFrommsg(r: IntArray, msg: ByteArray, msgOff: Int = 0) {
  for (i in 0 until MLKEM_N / 8) {
    for (j in 0 until 8) {
      val bit = (msg[msgOff + i].toInt() ushr j) and 1
      // cmov_int16: full-width mask = 0 or -1 (all bits set)
      val mask = -bit
      val v = (MLKEM_Q + 1) / 2 // 1665
      r[8 * i + j] = r[8 * i + j] xor (mask and (r[8 * i + j] xor v))
    }
  }
}

/**
 * Convert a polynomial to a 32-byte message (ref/poly.c `poly_tomsg`).
 *
 * Each coefficient is mapped to 0 or 1 via fixed-point rounding: `round(2 * coeff / Q)` using
 * `((coeff << 1) + 1665) * 80635 >> 28`.
 *
 * @param msg output 32-byte message (written from [msgOff])
 * @param msgOff offset in [msg]
 * @param a input polynomial coefficients (256 elements)
 */
internal fun polyTomsg(msg: ByteArray, msgOff: Int, a: IntArray) {
  for (i in 0 until MLKEM_N / 8) {
    var m = 0
    for (j in 0 until 8) {
      var t = a[8 * i + j].toLong()
      t = t shl 1
      t += 1665
      t *= 80635
      t = t shr 28
      t = t and 1
      m = m or (t.toInt() shl j)
    }
    msg[msgOff + i] = m.toByte()
  }
}

// ------------------------------------------------------------------
// NTT wrapper (ref/poly.c poly_ntt / poly_invntt_tomont / poly_tomont)
// ------------------------------------------------------------------

/**
 * Forward NTT (ref/poly.c `poly_ntt`): applies [MLKEMNtt.ntt] then [MLKEMNtt.polyReduce].
 *
 * Coefficients are in standard order on input, bitreversed order on output.
 *
 * @param a coefficient array of length 256; **modified in place**
 */
internal fun polyNtt(a: IntArray) {
  MLKEMNtt.ntt(a)
  MLKEMNtt.polyReduce(a)
}

/**
 * Inverse NTT + Montgomery normalization (ref/poly.c `poly_invntt_tomont`).
 *
 * Delegates to [MLKEMNtt.invnttTomont]. After this call, coefficients are in standard order but in
 * Montgomery domain (scaled by R = 2^16). A subsequent [MLKEMNtt.polyCaddq] + [MLKEMNtt.polyReduce]
 * brings them to standard form.
 *
 * @param a coefficient array of length 256; **modified in place**
 */
internal fun polyInvnttTomont(a: IntArray) {
  MLKEMNtt.invnttTomont(a)
}

/**
 * Convert coefficients to Montgomery domain (ref/poly.c `poly_tomont`).
 *
 * @param a coefficient array of length 256; **modified in place**
 */
internal fun polyTomont(a: IntArray) {
  MLKEMNtt.polyTomont(a)
}

// ------------------------------------------------------------------
// NTT-domain multiplication (ref/poly.c poly_basemul_montgomery)
// ------------------------------------------------------------------

/**
 * Multiplication of two polynomials in NTT domain (ref/poly.c `poly_basemul_montgomery`).
 *
 * For each group of 4 coefficients at positions (4*i, 4*i+1, 4*i+2, 4*i+3), computes two degree-2
 * products modulo X^2 ± zetas[64+i]:
 * - r[4i], r[4i+1] = basemul(a[4i..4i+1], b[4i..4i+1], zetas[64+i])
 * - r[4i+2], r[4i+3] = basemul(a[4i+2..4i+3], b[4i+2..4i+3], -zetas[64+i])
 *
 * Both inputs must be in NTT + Montgomery domain; output is in NTT + Montgomery domain.
 *
 * @param r output polynomial (256 elements, filled in place)
 * @param a first input polynomial in NTT domain
 * @param b second input polynomial in NTT domain
 */
internal fun polyBasemulMontgomery(r: IntArray, a: IntArray, b: IntArray) {
  for (i in 0 until MLKEM_N / 4) {
    val zeta = MLKEMNtt.zetas[64 + i].toInt()
    MLKEMNtt.basemul(r, 4 * i, a, 4 * i, b, 4 * i, zeta)
    MLKEMNtt.basemul(r, 4 * i + 2, a, 4 * i + 2, b, 4 * i + 2, -zeta)
  }
}

// ------------------------------------------------------------------
// Noise sampling (ref/poly.c poly_getnoise_eta1 / poly_getnoise_eta2)
// ------------------------------------------------------------------

/**
 * Sample an η1-bounded polynomial via SHAKE256 PRF (ref/poly.c `poly_getnoise_eta1`).
 *
 * The PRF is `SHAKE256(seed || nonce, outlen)` where `outlen = ETA1 * N / 4`. The output is passed
 * to [polyCbdEta1] (cbd3 for η1=3, cbd2 for η1=2).
 *
 * @param r output coefficient array (256 elements, filled in place)
 * @param seed 32-byte noise seed
 * @param nonce single-byte nonce
 */
internal fun polyGetnoiseEta1(r: IntArray, seed: ByteArray, seedOff: Int = 0, nonce: Int) {
  val outlen = MLKEM_ETA1 * MLKEM_N / 4
  val extkey = ByteArray(MLKEM_SYMBYTES + 1)
  seed.copyInto(extkey, 0, seedOff, seedOff + MLKEM_SYMBYTES)
  extkey[MLKEM_SYMBYTES] = nonce.toByte()
  val buf = SHAKE256PureK.digest(extkey, outlen)
  polyCbdEta1(r, buf)
}

/**
 * Sample an η2-bounded polynomial via SHAKE256 PRF (ref/poly.c `poly_getnoise_eta2`).
 *
 * The PRF is `SHAKE256(seed || nonce, outlen)` where `outlen = ETA2 * N / 4`. The output is passed
 * to [cbd2] (η2=2 for all ML-KEM parameter sets).
 *
 * @param r output coefficient array (256 elements, filled in place)
 * @param seed 32-byte noise seed
 * @param nonce single-byte nonce
 */
internal fun polyGetnoiseEta2(r: IntArray, seed: ByteArray, seedOff: Int = 0, nonce: Int) {
  val outlen = MLKEM_ETA2 * MLKEM_N / 4
  val extkey = ByteArray(MLKEM_SYMBYTES + 1)
  seed.copyInto(extkey, 0, seedOff, seedOff + MLKEM_SYMBYTES)
  extkey[MLKEM_SYMBYTES] = nonce.toByte()
  val buf = SHAKE256PureK.digest(extkey, outlen)
  polyCbdEta2(r, buf)
}

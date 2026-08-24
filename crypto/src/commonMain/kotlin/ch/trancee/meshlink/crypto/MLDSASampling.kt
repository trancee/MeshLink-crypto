/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-44 polynomial sampling and challenge (FIPS 204 §3.2, Algorithms 3–4).
 *
 * Pure-Kotlin implementation of:
 *
 * - [rejUniform]: rejection sampling for polynomials with coefficients in [0, Q−1]
 * - [polyUniform]: sample a degree-255 polynomial via SHAKE128 (FIPS 204 §3.3, Algorithm 3 / 4)
 * - [rejEta]: rejection sampling for small polynomials with coefficients in [−η, η]
 * - [polyUniformEta]: sample η-bounded polynomials via SHAKE256 (FIPS 204 §3.2, Algorithm 2)
 * - [polyUniformGamma1]: sample Γ₁-bounded polynomials via SHAKE256
 * - [polyChallenge]: produce the challenge polynomial c (FIPS 204 §3.2, Algorithm 1)
 *
 * The SHAKE streams use finalize()/squeeze() for incremental block production,
 * required when rejection sampling doesn't fill all 256 coefficients in the
 * first batch of SHAKE blocks.
 *
 * References:
 *   - FIPS 204 §3.2 (challenge generation and sampling)
 *   - FIPS 204 §3.3 (polynomial encoding and the matrix expansion)
 *   - pq-crystals/dilithium ref/poly.c (rejection sampling, challenge)
 *   - pq-crystals/dilithium ref/polyvec.c (matrix expansion)
 */
package ch.trancee.meshlink.crypto

/**
 * Rejection sampling for uniform mod-Q coefficients (FIPS 204, ref/rej_uniform).
 *
 * Reads 3-byte groups from [buf] (little-endian), masks to 23 bits (0x7FFFFF), and accepts
 * coefficients < Q into [out]. Returns the count of accepted coefficients.
 */
private fun rejUniform(out: IntArray, outOff: Int, buf: ByteArray, bufLen: Int): Int {
  var ctr = 0
  var pos = 0
  while (outOff + ctr < 256 && pos + 3 <= bufLen) {
    val t =
        ((buf[pos++].toInt() and 0xFF) or
            ((buf[pos++].toInt() and 0xFF) shl 8) or
            ((buf[pos++].toInt() and 0xFF) shl 16)) and 0x7FFFFF
    if (t < MLDSA_Q) {
      out[outOff + ctr] = t
      ctr++
    }
  }
  return ctr
}

/**
 * Rejection sampling for η-bounded coefficients (FIPS 204, ref/rej_eta).
 *
 * For η = 2, reads 4-bit nibbles, applies the mapping `t = t0 - (205*t0 >> 10)*5` to values < 15,
 * and maps to η − t.
 */
private fun rejEta(out: IntArray, outOff: Int, buf: ByteArray, bufLen: Int): Int {
  var ctr = 0
  var pos = 0
  while (outOff + ctr < 256 && pos < bufLen) {
    var t0 = buf[pos].toInt() and 0x0F
    var t1 = (buf[pos].toInt() and 0xFF) ushr 4
    pos++
    if (t0 < 15) {
      t0 -= ((205 * t0) ushr 10) * 5
      out[outOff + ctr] = MLDSA_ETA - t0
      ctr++
    }
    if (t1 < 15 && outOff + ctr < 256) {
      t1 -= ((205 * t1) ushr 10) * 5
      out[outOff + ctr] = MLDSA_ETA - t1
      ctr++
    }
  }
  return ctr
}

/**
 * Sample a uniform polynomial mod Q using SHAKE128 (FIPS 204 §3.2, Algorithm 3).
 *
 * Absorbs the 32-byte [seed] plus 2-byte little-endian [nonce], squeezes SHAKE128 blocks, and
 * applies rejection sampling until all 256 coefficients are produced.
 *
 * @param out output coefficient array (will be filled with 256 values in [0, Q−1])
 * @param seed 32-byte seed (ρ)
 * @param nonce 16-bit nonce (index in the matrix or signing context)
 */
internal fun polyUniform(out: IntArray, seed: ByteArray, nonce: Int) {
  val nonceBytes = ByteArray(2) { (nonce ushr (8 * it)).toByte() }
  val shakeInput = seed.copyOf() + nonceBytes

  val hasher = SHAKE128Hasher()
  hasher.update(shakeInput)
  hasher.finalize()

  // POLY_UNIFORM_NBLOCKS = ceil(768 / 168) = 5 blocks, 840 bytes
  var buf = hasher.squeeze(5 * SHAKE128_RATE)
  var bufLen = buf.size

  var ctr = rejUniform(out, 0, buf, bufLen)

  // Refill loop: squeeze one block at a time, carry over leftover bytes.
  while (ctr < 256) {
    val newBuf = hasher.squeeze(SHAKE128_RATE)
    val leftover = bufLen % 3
    val combined = ByteArray(leftover + SHAKE128_RATE)
    for (i in 0 until leftover) {
      combined[i] = buf[bufLen - leftover + i]
    }
    for (i in 0 until SHAKE128_RATE) {
      combined[leftover + i] = newBuf[i]
    }
    buf = combined
    bufLen = combined.size
    ctr += rejUniform(out, ctr, buf, bufLen)
  }
}

/**
 * Sample a polynomial with coefficients in [−η, η] using SHAKE256 (FIPS 204 §3.2, Algorithm 2).
 *
 * For η = 2, squeezes SHAKE256 blocks and applies rejection sampling.
 *
 * @param out output coefficient array (will be filled with 256 values in [−2, 2])
 * @param seed 64-byte seed (CRHBYTES)
 * @param nonce 16-bit nonce
 */
internal fun polyUniformEta(out: IntArray, seed: ByteArray, nonce: Int) {
  val nonceBytes = ByteArray(2) { (nonce ushr (8 * it)).toByte() }
  val shakeInput = seed.copyOf() + nonceBytes

  val hasher = SHAKE256Hasher()
  hasher.update(shakeInput)
  hasher.finalize()

  // POLY_UNIFORM_ETA_NBLOCKS for eta=2: ceil(136 / 136) = 1 block = 136 bytes
  var buf = hasher.squeeze(SHAKE256_RATE)
  var bufLen = buf.size

  var ctr = rejEta(out, 0, buf, bufLen)

  while (ctr < 256) {
    buf = hasher.squeeze(SHAKE256_RATE)
    bufLen = buf.size
    ctr += rejEta(out, ctr, buf, bufLen)
  }
}

/**
 * Sample a polynomial with coefficients in [−(Γ₁−1), Γ₁] using SHAKE256 (FIPS 204 §3.2).
 *
 * For Γ₁ = 2^17, packs 4 coefficients into 9 bytes (POLYZ_PACKEDBYTES = 576 bytes = 64 groups).
 * Squeezes enough SHAKE256 blocks and unpacks directly.
 *
 * @param out output coefficient array (will be filled with 256 values)
 * @param seed 64-byte seed (CRHBYTES)
 * @param nonce 16-bit nonce
 */
internal fun polyUniformGamma1(out: IntArray, seed: ByteArray, nonce: Int) {
  val nonceBytes = ByteArray(2) { (nonce ushr (8 * it)).toByte() }
  val shakeInput = seed.copyOf() + nonceBytes

  val hasher = SHAKE256Hasher()
  hasher.update(shakeInput)
  hasher.finalize()

  // POLY_UNIFORM_GAMMA1_NBLOCKS = ceil(576 / 136) = 5 blocks = 680 bytes
  val buf = hasher.squeeze(5 * SHAKE256_RATE)
  polyZUnpack(out, buf, 0)
}

/**
 * Generate the challenge polynomial c (FIPS 204 §3.2, Algorithm 1).
 *
 * Uses SHAKE256 to produce a pseudorandom mask, then constructs a polynomial with τ non-zero
 * coefficients at positions determined by rejection sampling. The signs of the non-zero
 * coefficients are extracted from the low bits of the SHAKE output.
 *
 * @param out output coefficient array (will be a challenge polynomial)
 * @param seed 32-byte seed (CTILDEBYTES)
 */
internal fun polyChallenge(out: IntArray, seed: ByteArray) {
  val hasher = SHAKE256Hasher()
  hasher.update(seed)
  hasher.finalize()

  // Squeeze one block (136 bytes)
  val buf = ByteArray(SHAKE256_RATE)
  val firstBlock = hasher.squeeze(SHAKE256_RATE)
  for (i in 0 until SHAKE256_RATE) buf[i] = firstBlock[i]

  // Extract signs: first 8 bytes give 64 bits of sign data
  var signs = 0L
  for (i in 0 until 8) {
    signs = signs or ((buf[i].toLong() and 0xFFL) shl (8 * i))
  }

  // Initialize polynomial to zero
  for (i in out.indices) {
    out[i] = 0
  }

  var pos = 8
  for (i in (256 - MLDSA_TAU)..255) {
    var b: Int
    do {
      if (pos >= SHAKE256_RATE) {
        val newBuf = hasher.squeeze(SHAKE256_RATE)
        for (j in 0 until SHAKE256_RATE) buf[j] = newBuf[j]
        pos = 0
      }
      b = buf[pos++].toInt() and 0xFF
    } while (b > i)

    out[i] = out[b]
    out[b] = if ((signs and 1L) == 0L) 1 else -1
    signs = signs ushr 1
  }
}

/**
 * Expand the K×L matrix A using SHAKE128 over the seed ρ (FIPS 204 §3.3, Algorithm 4).
 *
 * Each entry A[i][j] is a polynomial sampled via [polyUniform] with the appropriate nonce. The
 * nonce for row i, column j is `i*256 + j`, matching the C reference `(i << 8) + j`.
 *
 * @param rows output array of K rows, each containing L polynomials of 256 coeffs
 * @param seed 32-byte seed (ρ)
 */
internal fun polyvecMatrixExpand(rows: Array<Array<IntArray>>, seed: ByteArray) {
  for (i in 0 until MLDSA_K) {
    for (j in 0 until MLDSA_L) {
      polyUniform(rows[i][j], seed, i * 256 + j)
    }
  }
}

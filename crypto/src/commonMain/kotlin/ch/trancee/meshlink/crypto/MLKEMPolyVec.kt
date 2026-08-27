/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 polynomial-vector operations (FIPS 203 §6.2, ref/polyvec.c).
 *
 * Pure-Kotlin implementation of vector (length-K = 2) operations: compression,
 * serialization, NTT delegation, Montgomery-domain dot product, and lazy reduction.
 *
 * Vectors are represented as `Array<IntArray>` of length [MLKEM_K], each element
 * a 256-element coefficient array. All reduction paths are branch-free on secret
 * data (ADR-0003).
 *
 * Reference: pq-crystals/kyber ref/polyvec.c
 */
package ch.trancee.meshlink.crypto

// ------------------------------------------------------------------
// Vector compression (ref/polyvec.c polyvec_compress / polyvec_decompress)
// ------------------------------------------------------------------

/**
 * Compress and serialize a K-element vector of polynomials (ref/polyvec.c `polyvec_compress`).
 *
 * Each coefficient is compressed to 10 bits and packed: 4 coefficients per 5 bytes. Total output:
 * K * 320 = 640 bytes.
 *
 * Fixed-point implementation matches ref/polyvec.c exactly:
 * ```
 * d0 = (t << 10) + 1665;   // 1665 = Q/2 rounded up
 * d0 *= 1290167;            // 1290167 ≈ 2^32 / Q
 * d0 >>= 32;                // divide by 2^32
 * t = d0 & 0x3FF;
 * ```
 *
 * @param r output byte array (640 bytes, written from [rOff])
 * @param rOff offset in [r]
 * @param a input vector of K polynomials (each 256 elements)
 */
internal fun polyvecCompress(r: ByteArray, rOff: Int, a: Array<IntArray>) {
  var offset = rOff
  for (i in 0 until MLKEM_K) {
    for (j in 0 until MLKEM_N / 4) {
      val t = IntArray(4)
      for (k in 0 until 4) {
        var tk = a[i][4 * j + k]
        tk += (tk shr 31) and MLKEM_Q
        var d0 = tk.toLong() shl 10
        d0 += 1665
        d0 *= 1290167
        d0 = d0 shr 32
        t[k] = (d0 and 0x3FF).toInt()
      }
      r[offset + 0] = (t[0] and 0xFF).toByte()
      r[offset + 1] = ((t[0] ushr 8) or (t[1] shl 2)).toByte()
      r[offset + 2] = ((t[1] ushr 6) or (t[2] shl 4)).toByte()
      r[offset + 3] = ((t[2] ushr 4) or (t[3] shl 6)).toByte()
      r[offset + 4] = ((t[3] ushr 2) and 0xFF).toByte()
      offset += 5
    }
  }
}

/**
 * De-serialize and decompress a K-element vector of polynomials (ref/polyvec.c
 * `polyvec_decompress`).
 *
 * Inverse of [polyvecCompress]. Each group of 5 bytes yields 4 coefficients, expanded from 10 bits
 * to full-width via `round(t * Q / 1024)`.
 *
 * @param r output vector of K polynomials (each 256 elements, filled in place)
 * @param a input byte array
 * @param aOff offset in [a]
 */
internal fun polyvecDecompress(r: Array<IntArray>, a: ByteArray, aOff: Int) {
  var offset = aOff
  for (i in 0 until MLKEM_K) {
    for (j in 0 until MLKEM_N / 4) {
      val t = IntArray(4)
      t[0] =
          ((a[offset + 0].toInt() and 0xFF) or ((a[offset + 1].toInt() and 0xFF) shl 8)) and 0x3FF
      t[1] =
          ((a[offset + 1].toInt() and 0xFF) ushr 2 or ((a[offset + 2].toInt() and 0xFF) shl 6)) and
              0x3FF
      t[2] =
          ((a[offset + 2].toInt() and 0xFF) ushr 4 or ((a[offset + 3].toInt() and 0xFF) shl 4)) and
              0x3FF
      t[3] =
          ((a[offset + 3].toInt() and 0xFF) ushr 6 or ((a[offset + 4].toInt() and 0xFF) shl 2)) and
              0x3FF
      offset += 5

      for (k in 0 until 4) {
        r[i][4 * j + k] = ((t[k].toLong() * MLKEM_Q + 512) shr 10).toInt()
      }
    }
  }
}

// ------------------------------------------------------------------
// Vector serialization (ref/polyvec.c polyvec_tobytes / polyvec_frombytes)
// ------------------------------------------------------------------

/**
 * Serialize a K-element vector of polynomials to raw bytes (ref/polyvec.c `polyvec_tobytes`).
 *
 * Each polynomial is serialized via [polyTobytes] (384 bytes), giving K * 384 = 768 bytes.
 *
 * @param r output byte array (768 bytes, written from [rOff])
 * @param rOff offset in [r]
 * @param a input vector of K polynomials
 */
internal fun polyvecTobytes(r: ByteArray, rOff: Int, a: Array<IntArray>) {
  for (i in 0 until MLKEM_K) {
    polyTobytes(r, rOff + i * MLKEM_POLYBYTES, a[i])
  }
}

/**
 * De-serialize a K-element vector of polynomials from raw bytes (ref/polyvec.c
 * `polyvec_frombytes`).
 *
 * Inverse of [polyvecTobytes].
 *
 * @param r output vector of K polynomials (each 256 elements, filled in place)
 * @param a input byte array
 * @param aOff offset in [a]
 */
internal fun polyvecFrombytes(r: Array<IntArray>, a: ByteArray, aOff: Int) {
  for (i in 0 until MLKEM_K) {
    polyFrombytes(r[i], a, aOff + i * MLKEM_POLYBYTES)
  }
}

// ------------------------------------------------------------------
// Vector NTT (ref/poly.c polyvec_ntt / polyvec_invntt_tomont)
// ------------------------------------------------------------------

/**
 * Apply forward NTT to all polynomials in a vector (ref/polyvec.c `polyvec_ntt`).
 *
 * @param a vector of K polynomials; **modified in place**
 */
internal fun polyvecNtt(a: Array<IntArray>) {
  for (i in a.indices) {
    polyNtt(a[i])
  }
}

/**
 * Apply inverse NTT with Montgomery normalization to all polynomials in a vector (ref/polyvec.c
 * `polyvec_invntt_tomont`).
 *
 * @param a vector of K polynomials; **modified in place**
 */
internal fun polyvecInvnttTomont(a: Array<IntArray>) {
  for (i in a.indices) {
    polyInvnttTomont(a[i])
  }
}

// ------------------------------------------------------------------
// Vector reduction (ref/polyvec.c polyvec_reduce / polyvec_add)
// ------------------------------------------------------------------

/** In-place lazy reduction of all polynomials in a vector (ref/polyvec.c `polyvec_reduce`). */
internal fun polyvecReduce(a: Array<IntArray>) {
  for (i in a.indices) {
    MLKEMNtt.polyReduce(a[i])
  }
}

/** Add two vectors: r = u + v (no modular reduction; caller must reduce later). */
internal fun polyvecAdd(r: Array<IntArray>, u: Array<IntArray>, v: Array<IntArray>) {
  for (i in r.indices) {
    MLKEMNtt.polyAdd(r[i], u[i], v[i])
  }
}

// ------------------------------------------------------------------
// NTT-domain dot product (ref/polyvec.c polyvec_basemul_acc_montgomery)
// ------------------------------------------------------------------

/**
 * Dot product of two vectors in NTT + Montgomery domain (ref/polyvec.c
 * `polyvec_basemul_acc_montgomery`).
 *
 * Computes `r = Σ_i a[i] ⊛ b[i]` where ⊛ is the NTT-domain multiplication via
 * [polyBasemulMontgomery], then applies [MLKEMNtt.polyReduce] to bring coefficients into the
 * centered range.
 *
 * @param r output polynomial (256 elements)
 * @param a first input vector in NTT domain
 * @param b second input vector in NTT domain
 */
internal fun polyvecBasemulAccMontgomery(r: IntArray, a: Array<IntArray>, b: Array<IntArray>) {
  polyBasemulMontgomery(r, a[0], b[0])
  for (i in 1 until MLKEM_K) {
    val t = IntArray(MLKEM_N)
    polyBasemulMontgomery(t, a[i], b[i])
    MLKEMNtt.polyAdd(r, r, t)
  }
  MLKEMNtt.polyReduce(r)
}

/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-44 vector-level polynomial operations (FIPS 204 §3, ref/polyvec.c).
 *
 * Pure-Kotlin implementation of the vector (row/column of polynomials)
 * operations over the module lattice:
 *
 * - L-vector (length ℓ = 4): s1, s2, z, y, etc.
 * - K-vector (length k = 4): t1, t0, w, w0, w1, h, etc.
 *
 * Operations include NTT domain conversion, pointwise Montgomery
 * multiplication, vector arithmetic (add, sub, reduce, caddq), norm checks,
 * and the rounding/hint mechanism (power2round, decompose, makeHint, useHint).
 *
 * All operations assume the underlying per-polynomial functions in
 * [MLDSAPoly.kt] and NTT engine in [MLDSANtt.kt]. Branch-free reduction
 * paths are used throughout; no data-dependent branching touches secret
 * coefficients (ADR-0003).
 *
 * References:
 *   - FIPS 204 §3 (ML-DSA internal module arithmetic)
 *   - pq-crystals/dilithium ref/polyvec.c
 */
package ch.trancee.meshlink.crypto

// ------------------------------------------------------------------
// L-vector operations (length ℓ = 4): s1, s2, z, y, etc.
// ------------------------------------------------------------------

/** Apply NTT to each polynomial in the ℓ-vector (FIPS 204, ref/polyvecl_ntt). */
internal fun polyveclNtt(v: Array<IntArray>) {
  for (i in v.indices) {
    MLDSANtt.ntt(v[i])
  }
}

/**
 * Apply inverse NTT (with Montgomery multiplication by f=41978) to each polynomial in the ℓ-vector
 * (FIPS 204, ref/polyvecl_invntt_tomont).
 */
internal fun polyveclInvnttTomont(v: Array<IntArray>) {
  for (i in v.indices) {
    MLDSANtt.invnttTomont(v[i])
  }
}

/**
 * Pointwise Montgomery multiplication of an ℓ-vector (in NTT domain) with a matrix row,
 * accumulating into a K-vector (FIPS 204, ref/polyvec_matrix_expand).
 *
 * Computes w1[i] = sum_j mat[i][j] * z[j] via NTT-domain pointwise multiplication.
 *
 * @param w1 output K-vector (accumulated result)
 * @param mat K×L matrix of NTT-domain polynomials
 * @param z input ℓ-vector in NTT domain
 */
internal fun polyveclPointwiseAccMontgomery(
    w1: Array<IntArray>,
    mat: Array<Array<IntArray>>,
    z: Array<IntArray>,
) {
  for (i in 0 until MLDSA_K) {
    // w1[i] = mat[i][0] * z[0]
    polyPointwiseMontgomery(w1[i], mat[i][0], z[0])
    // w1[i] += mat[i][j] * z[j] for j = 1..L-1
    for (j in 1 until MLDSA_L) {
      val tmp = IntArray(256)
      polyPointwiseMontgomery(tmp, mat[i][j], z[j])
      polyAdd(w1[i], w1[i], tmp)
    }
  }
}

/**
 * Check infinity norm of ℓ-vector (FIPS 204, ref/polyvecl_chknorm).
 *
 * Returns true if any coefficient's absolute value ≥ [bound].
 */
internal fun polyveclChknorm(v: Array<IntArray>, bound: Int): Boolean {
  for (i in v.indices) {
    if (polyChknorm(v[i], bound)) return true
  }
  return false
}

/**
 * Pointwise Montgomery multiply each polynomial in an ℓ-vector by [a] (FIPS 204,
 * ref/polyvecl_pointwise_poly_montgomery).
 */
internal fun polyveclPointwisePolyMontgomery(r: Array<IntArray>, a: IntArray, v: Array<IntArray>) {
  for (i in r.indices) {
    polyPointwiseMontgomery(r[i], a, v[i])
  }
}

/** Add two ℓ-vectors: w = u + v. */
internal fun polyveclAdd(w: Array<IntArray>, u: Array<IntArray>, v: Array<IntArray>) {
  for (i in w.indices) {
    polyAdd(w[i], u[i], v[i])
  }
}

/** In-place lazy reduction of all polynomials in an ℓ-vector. */
internal fun polyveclReduce(v: Array<IntArray>) {
  for (i in v.indices) {
    polyReduce(v[i])
  }
}

/** Sample uniform η-bounded polynomials into an ℓ-vector (ref/polyvecl_uniform_eta). */
internal fun polyveclUniformEta(v: Array<IntArray>, seed: ByteArray, nonce: Int) {
  for (i in v.indices) {
    polyUniformEta(v[i], seed, nonce + i)
  }
}

/** Sample uniform Γ₁-bounded polynomials into an ℓ-vector (ref/polyvecl_uniform_gamma1). */
internal fun polyveclUniformGamma1(v: Array<IntArray>, seed: ByteArray, nonce: Int) {
  for (i in v.indices) {
    polyUniformGamma1(v[i], seed, MLDSA_L * nonce + i)
  }
}

/** Sample uniform η-bounded polynomials into a K-vector (ref/polyveck_uniform_eta). */
internal fun polyveckUniformEta(v: Array<IntArray>, seed: ByteArray, nonce: Int) {
  for (i in v.indices) {
    polyUniformEta(v[i], seed, nonce + i)
  }
}

// ------------------------------------------------------------------
// K-vector operations (length k = 4): t1, t0, w, w0, w1, h
// ------------------------------------------------------------------

/** Apply NTT to each polynomial in the K-vector. */
internal fun polyveckNtt(v: Array<IntArray>) {
  for (i in v.indices) {
    MLDSANtt.ntt(v[i])
  }
}

/** Apply inverse NTT to each polynomial in the K-vector. */
internal fun polyveckInvnttTomont(v: Array<IntArray>) {
  for (i in v.indices) {
    MLDSANtt.invnttTomont(v[i])
  }
}

/**
 * Pointwise Montgomery multiply a K-vector by a single polynomial (FIPS 204,
 * ref/polyveck_pointwise_poly_montgomery).
 */
internal fun polyveckPointwisePolyMontgomery(w: Array<IntArray>, a: IntArray, v: Array<IntArray>) {
  for (i in w.indices) {
    polyPointwiseMontgomery(w[i], a, v[i])
  }
}

/** Subtract two K-vectors: w = u − v (FIPS 204, ref/polyveck_sub). */
internal fun polyveckSub(w: Array<IntArray>, u: Array<IntArray>, v: Array<IntArray>) {
  for (i in w.indices) {
    polySub(w[i], u[i], v[i])
  }
}

/** Add two K-vectors: w = u + v. */
internal fun polyveckAdd(w: Array<IntArray>, u: Array<IntArray>, v: Array<IntArray>) {
  for (i in w.indices) {
    polyAdd(w[i], u[i], v[i])
  }
}

/** In-place lazy reduction of all polynomials in a K-vector (ref/polyveck_reduce). */
internal fun polyveckReduce(v: Array<IntArray>) {
  for (i in v.indices) {
    polyReduce(v[i])
  }
}

/** In-place conditional add-Q on all polynomials in a K-vector (ref/polyveck_caddq). */
internal fun polyveckCaddq(v: Array<IntArray>) {
  for (i in v.indices) {
    polyCaddq(v[i])
  }
}

/**
 * Power-of-2 rounding on all polynomials in a K-vector (FIPS 204, ref/polyveck_power2round).
 *
 * Produces v1 (high bits, t1) and v0 (low bits, t0) from v. Note: [power2round] signature is
 * (a1Out, a0Out, a) — high bits first, low bits second.
 */
internal fun polyveckPower2round(v1: Array<IntArray>, v0: Array<IntArray>, v: Array<IntArray>) {
  for (i in 0 until MLDSA_K) {
    power2round(v1[i], v0[i], v[i])
  }
}

/**
 * Power-of-2 rounding on all polynomials in a K-vector (FIPS 204, ref/polyveck_power2round).
 *
 * Produces v1 (high bits, t1) and v0 (low bits, t0) from v.
 */

/**
 * Decomposition on all polynomials in a K-vector (FIPS 204, ref/polyveck_decompose).
 *
 * Produces v1 (high bits) and v0 (low bits) from v using α = 2·Γ₂.
 */
internal fun polyveckDecompose(v1: Array<IntArray>, v0: Array<IntArray>, v: Array<IntArray>) {
  for (i in 0 until MLDSA_K) {
    decompose(v1[i], v0[i], v[i])
  }
}

/**
 * Make hint across all polynomials in a K-vector (FIPS 204, ref/polyveck_make_hint).
 *
 * Returns the total number of hints set.
 */
internal fun polyveckMakeHint(h: Array<IntArray>, v0: Array<IntArray>, v1: Array<IntArray>): Int {
  var s = 0
  for (i in 0 until MLDSA_K) {
    for (j in 0 until 256) {
      val hint = makeHint(v0[i][j], v1[i][j])
      h[i][j] = hint
      s += hint
    }
  }
  return s
}

/**
 * Use hint to correct high bits across all polynomials in a K-vector (FIPS 204,
 * ref/polyveck_use_hint).
 */
internal fun polyveckUseHint(w: Array<IntArray>, u: Array<IntArray>, h: Array<IntArray>) {
  for (i in 0 until MLDSA_K) {
    for (j in 0 until 256) {
      w[i][j] = useHint(u[i][j], h[i][j])
    }
  }
}

/**
 * Pack w1 polynomials into byte representation for the challenge hash (FIPS 204,
 * ref/polyveck_packw1).
 */
internal fun polyveckPackW1(buf: ByteArray, bufOff: Int, w1: Array<IntArray>) {
  var off = bufOff
  for (i in 0 until MLDSA_K) {
    polyW1Pack(buf, off, w1[i])
    off += MLDSA_POLYW1_PACKEDBYTES
  }
}

/**
 * Check infinity norm of a K-vector (ref/polyveck_chknorm). Returns true if any coefficient's
 * absolute value >= [bound].
 */
internal fun polyveckChknorm(v: Array<IntArray>, bound: Int): Boolean {
  for (i in v.indices) {
    if (polyChknorm(v[i], bound)) return true
  }
  return false
}

/**
 * Shift-left t1 polynomials in a K-vector by D bits (FIPS 204, ref/polyveck_shiftl).
 *
 * Used in verification to align t1 coefficients before NTT multiplication.
 */
internal fun polyveckShiftl(v: Array<IntArray>) {
  for (i in v.indices) {
    polyShiftl(v[i])
  }
}

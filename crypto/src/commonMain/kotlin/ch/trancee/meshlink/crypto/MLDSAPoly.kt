/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-44 polynomial operations (FIPS 204 §3, Algorithms 8–15).
 *
 * Pure-Kotlin implementation of per-polynomial arithmetic: reduction, addition,
 * subtraction, pointwise Montgomery multiplication, NTT delegation, infinity-norm
 * check, and the power2round/decompose/hint primitives for the rounding-based
 * error recovery mechanism.
 *
 * All functions are `internal` — callers operate through [MLDSAPolyVec] and
 * [MLDSA44PureK]. Branch-free reduction paths are inherited from [MLDSANtt];
 * no data-dependent branching touches secret coefficients (ADR-0003).
 *
 * Reference: pq-crystals/dilithium ref/poly.c, ref/reduce.c, ref/rounding.c
 */
package ch.trancee.meshlink.crypto

/**
 * Field modulus Q = 8380417 (FIPS 204 §3, Table 1). Shared constant used across all ML-DSA
 * polynomial operations.
 */
internal const val MLDSA_Q: Int = 8380417

/** Square root of Q minus one: D = 13 (FIPS 204 §3). t1 = (t + 2^(D-1)) >> D, t0 = t - t1 * 2^D. */
internal const val MLDSA_D: Int = 13

/**
 * ML-DSA parameter: η = 2 (FIPS 204 §4.1, Table 2 for ML-DSA-44). Coefficients of s1, s2 are in
 * [-η, η] = [-2, 2].
 */
internal const val MLDSA_ETA: Int = 2

/**
 * ML-DSA parameter: Γ₁ = 2^17 (FIPS 204 §4.1, Table 2 for ML-DSA-44). Coefficients of z are in
 * [-(Γ₁-1), Γ₁] = [-131071, 131072].
 */
internal const val MLDSA_GAMMA1: Int = 1 shl 17

/**
 * ML-DSA parameter: Γ₂ = (Q−1)/88 (FIPS 204 §4.1, Table 2 for ML-DSA-44). Used in the
 * decompose/make-hint mechanism.
 */
internal const val MLDSA_GAMMA2: Int = (MLDSA_Q - 1) / 88

/**
 * ML-DSA parameter: τ = 39 (FIPS 204 §4.1, Table 2 for ML-DSA-44). Challenge polynomial has τ
 * non-zero coefficients.
 */
internal const val MLDSA_TAU: Int = 39

/**
 * ML-DSA parameter: β = 2η = 78 (FIPS 204 §4.1, Table 2 for ML-DSA-44). Rejection bound: |z| < Γ₁ −
 * β must hold after signing.
 */
internal const val MLDSA_BETA: Int = 78

/**
 * ML-DSA parameter: ω = 80 (FIPS 204 §4.1, Table 2 for ML-DSA-44). Maximum number of non-zero hint
 * coefficients across all K polynomials.
 */
internal const val MLDSA_OMEGA: Int = 80

/** ML-DSA parameter: k = 4, ℓ = 4 (FIPS 204 §4.1, Table 2 for ML-DSA-44). */
internal const val MLDSA_K: Int = 4
internal const val MLDSA_L: Int = 4

/** ML-DSA parameter: N = 256 (FIPS 204 §3, the polynomial degree). */
internal const val N: Int = 256

/** Seed size in bytes (FIPS 204 §4.2, ρ, key, etc.). */
internal const val MLDSA_SEEDBYTES: Int = 32

/** Challenge hash size in bytes (FIPS 204 §4.2, c̃). */
internal const val MLDSA_CTILDEBYTES: Int = 32

/** Hash output size for CRH (SHAKE256) in bytes (FIPS 204 §4.2, μ, r'). */
internal const val MLDSA_CRHBYTES: Int = 64

/** Hash output size for H (SHAKE256) in bytes (FIPS 204 §4.2, tr). */
internal const val MLDSA_TRBYTES: Int = 64

/** Packed size of a t1 polynomial: 10-bit coefficients × 256 = 320 bytes (FIPS 204 §3, 4*N/8*5). */
internal const val MLDSA_POLYT1_PACKEDBYTES: Int = 320

/** Packed size of a t0 polynomial: 13-bit coefficients × 256 / 8 = 416 bytes. */
internal const val MLDSA_POLYT0_PACKEDBYTES: Int = 416

/**
 * Packed size of a z polynomial (Γ₁ = 2^17, 18-bit coefficients): 9 bytes per group of 4 = 576
 * bytes.
 */
internal const val MLDSA_POLYZ_PACKEDBYTES: Int = 576

/** Packed size of a w1 polynomial: 6-bit coefficients × 256 / 8 = 192 bytes. */
internal const val MLDSA_POLYW1_PACKEDBYTES: Int = 192

/**
 * Packed size of an η-polynomial (η = 2, 3-bit coefficients): 3 bytes per group of 8 = 96 bytes.
 */
internal const val MLDSA_POLYETA_PACKEDBYTES: Int = 96

/** Public key size: ρ (32) + K × POLYT1_PACKEDBYTES = 32 + 4 × 320 = 1312 bytes. */
internal const val MLDSA_PUBLICKEYBYTES: Int = MLDSA_SEEDBYTES + MLDSA_K * MLDSA_POLYT1_PACKEDBYTES

/**
 * Secret key size: ρ (32) + key (32) + tr (64) + L × POLYETA (96) + K × POLYETA (96) + K × POLYT0
 * (416) = 2560 bytes.
 */
internal const val MLDSA_SECRETKEYBYTES: Int =
    MLDSA_SEEDBYTES +
        MLDSA_SEEDBYTES +
        MLDSA_TRBYTES +
        MLDSA_L * MLDSA_POLYETA_PACKEDBYTES +
        MLDSA_K * MLDSA_POLYETA_PACKEDBYTES +
        MLDSA_K * MLDSA_POLYT0_PACKEDBYTES

/** Signature size: c̃ (32) + L × POLYZ (576) + OMEGA + K = 32 + 4 × 576 + 80 + 4 = 2420 bytes. */
internal const val MLDSA_BYTES: Int =
    MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES + MLDSA_OMEGA + MLDSA_K

/** α = 2·Γ₂ = (Q−1)/44 (FIPS 204 §3, used in decompose). */
internal const val MLDSA_ALPHA: Int = 2 * MLDSA_GAMMA2

// ------------------------------------------------------------------
// Scalar rounding (FIPS 204 Algorithms 13–15, ref/rounding.c)
// ------------------------------------------------------------------

/**
 * Power-of-2 rounding (FIPS 204 Algorithm 13): decompose *a* into *a1*·2^D + *a0* with −2^(D−1) <
 * a0 ≤ 2^(D−1).
 *
 * Writes *a1* (high bits) into [a1Out] and *a0* (low bits) into [a0Out]. Assumes [a] is a standard
 * representative in [0, Q−1].
 *
 * **Aliasing-safe**: reads [a] into a local before writing [a1Out], so the caller may pass the same
 * IntArray for [a1Out] and [a] (as the C reference does in `polyveck_power2round(&t1, &t0, &t1)`).
 */
internal fun power2round(a1Out: IntArray, a0Out: IntArray, a: IntArray) {
  for (i in a.indices) {
    val orig = a[i]
    a1Out[i] = (orig + (1 shl (MLDSA_D - 1)) - 1) shr MLDSA_D
    a0Out[i] = orig - (a1Out[i] shl MLDSA_D)
  }
}

/**
 * High/low decomposition (FIPS 204 Algorithm 13 → decompose): split *a* into a1 = decompose hi, a0
 * = decompose lo, where a mod Q = a1·α + a0 with −α/2 < a0 ≤ α/2 (except a1 = (Q−1)/α where a1 is
 * set to 0).
 *
 * Writes *a1* into [a1Out] and *a0* into [a0Out]. Assumes [a] coefficients are standard
 * representatives in [0, Q−1].
 */
internal fun decompose(a1Out: IntArray, a0Out: IntArray, a: IntArray) {
  for (i in a.indices) {
    var a1 = (a[i] + 127) shr 7
    a1 = (a1 * 11275 + (1 shl 23)) shr 24
    a1 = a1 xor ((43 - a1) shr 31) and a1

    a0Out[i] = a[i] - a1 * 2 * MLDSA_GAMMA2
    a0Out[i] -= (((MLDSA_Q - 1) / 2 - a0Out[i]) shr 31) and MLDSA_Q
    a1Out[i] = a1
  }
}

/**
 * Make-hint bit (FIPS 204 Algorithm 14): returns 1 if the low bits [a0] overflow into the high bits
 * [a1], i.e. if a0 > Γ₂ or (a0 == −Γ₂ and a1 ≠ 0).
 *
 * Returns h ∈ {0, 1}.
 */
internal fun makeHint(a0: Int, a1: Int): Int {
  return if (a0 > MLDSA_GAMMA2 || a0 < -MLDSA_GAMMA2 || (a0 == -MLDSA_GAMMA2 && a1 != 0)) 1 else 0
}

/**
 * Use-hint (FIPS 204 Algorithm 15): correct the high bits using the hint bit [hint].
 *
 * Decomposes [a] into (a1, a0), then:
 * - If [hint] == 0: returns a1 unchanged.
 * - If [hint] == 1 and a0 > 0: returns a1 + 1, with wrap-around at a1 == 43 → 0.
 * - If [hint] == 1 and a0 <= 0: returns a1 - 1, with wrap-around at a1 == 0 → 43.
 *
 * Matches C reference: ref/rounding.c use_hint(), which calls decompose() to obtain both a0 and a1.
 *
 * @param a the input coefficient (standard representative in [0, Q−1])
 * @param hint hint bit (0 or 1)
 * @return corrected high bits in [0, 43]
 */
internal fun useHint(a: Int, hint: Int): Int {
  var a1 = (a + 127) shr 7
  a1 = (a1 * 11275 + (1 shl 23)) shr 24
  a1 = a1 xor ((43 - a1) shr 31) and a1

  var a0 = a - a1 * 2 * MLDSA_GAMMA2
  a0 -= (((MLDSA_Q - 1) / 2 - a0) shr 31) and MLDSA_Q

  if (hint == 0) return a1
  return if (a0 > 0) {
    if (a1 == 43) 0 else a1 + 1
  } else {
    if (a1 == 0) 43 else a1 - 1
  }
}

// ------------------------------------------------------------------
// Polynomial-level operations (FIPS 204, ref/poly.c)
// ------------------------------------------------------------------

/**
 * In-place lazy reduction of all 256 coefficients to [−6283008, 6283008] via [MLDSANtt.reduce32].
 */
internal fun polyReduce(a: IntArray) {
  for (i in a.indices) {
    a[i] = MLDSANtt.reduce32(a[i])
  }
}

/** In-place conditional add-Q: adds Q to each negative coefficient via [MLDSANtt.caddq]. */
internal fun polyCaddq(a: IntArray) {
  for (i in a.indices) {
    a[i] = MLDSANtt.caddq(a[i])
  }
}

/** c = a + b (no modular reduction; caller must reduce later). */
internal fun polyAdd(c: IntArray, a: IntArray, b: IntArray) {
  for (i in c.indices) {
    c[i] = a[i] + b[i]
  }
}

/** c = a − b (no modular reduction; caller must reduce later). */
internal fun polySub(c: IntArray, a: IntArray, b: IntArray) {
  for (i in c.indices) {
    c[i] = a[i] - b[i]
  }
}

/**
 * Shift-left: a[i] *= 2^D in-place (no modular reduction). Used for t1 before NTT multiplication in
 * verification.
 */
internal fun polyShiftl(a: IntArray) {
  for (i in a.indices) {
    a[i] = a[i] shl MLDSA_D
  }
}

/**
 * Pointwise Montgomery multiplication (FIPS 204 Algorithm 9): c[i] = montgomeryReduce(a[i] · b[i])
 * for each coefficient. Both inputs must be in NTT + Montgomery domain; output is in NTT +
 * Montgomery domain.
 */
internal fun polyPointwiseMontgomery(c: IntArray, a: IntArray, b: IntArray) {
  for (i in c.indices) {
    c[i] = MLDSANtt.montgomeryReduce(a[i].toLong() * b[i])
  }
}

/**
 * Infinity-norm check (FIPS 204 Algorithm 8): returns true if ||a||_∞ is strictly less than
 * [bound], i.e. all |coeffs[i]| < bound.
 *
 * Assumes coefficients were reduced by [polyReduce] first. The bound must satisfy bound ≤ (Q−1)/8.
 */
internal fun polyChknorm(a: IntArray, bound: Int): Boolean {
  for (i in a.indices) {
    val sign = a[i] shr 31 // -1 if negative, 0 if non-negative
    val t = a[i] - (sign and (2 * a[i])) // |a[i]|
    if (t >= bound) return true
  }
  return false
}

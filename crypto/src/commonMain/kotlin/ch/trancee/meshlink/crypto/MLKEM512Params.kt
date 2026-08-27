/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 parameter constants (FIPS 203 §6.1, ref/params.h).
 *
 * Pure-Kotlin constants for the K=2 (n=256, q=3329) module lattice. No runtime
 * computation. All values match the pq-crystals/kyber ref/params.h for
 * KYBER_K=2 exactly.
 */
package ch.trancee.meshlink.crypto

// ------------------------------------------------------------------
// Core parameters (FIPS 203 §6.1, ref/params.h)
// ------------------------------------------------------------------

/** Module dimension K = 2 (FIPS 203 §6.1, Table 1 for ML-KEM-512). */
internal const val MLKEM_K: Int = 2

/** Polynomial degree N = 256 (shared across all ML-KEM parameter sets). */
internal const val MLKEM_N: Int = 256

/** Field modulus Q = 3329 (FIPS 203 §6.1). */
internal const val MLKEM_Q: Int = 3329

/** Q^{-1} mod 2^16 = -3327 (used by Montgomery reduction with R = 2^16). */
internal const val MLKEM_QINV: Int = -3327

/** R = 2^16 mod Q = -1044 (Montgomery factor for entering/leaving Montgomery domain). */
internal const val MLKEM_MONT: Int = -1044

/** Normalization factor after inverse NTT: f = 1441 = R^2 / 2^8 mod Q (ref/ntt.c `invntt`). */
internal const val MLKEM_NTT_F: Int = 1441

/** Seed size in bytes (ρ, key, H(pk), etc.). */
internal const val MLKEM_SYMBYTES: Int = 32

/** Shared secret size in bytes. */
internal const val MLKEM_SSBYTES: Int = 32

/** Noise parameter η1 = 3 for ML-KEM-512 (ref/params.h, KYBER_ETA1). */
internal const val MLKEM_ETA1: Int = 3

/** Noise parameter η2 = 2 (ref/params.h, KYBER_ETA2). */
internal const val MLKEM_ETA2: Int = 2

// ------------------------------------------------------------------
// Byte sizes (ref/params.h)
// ------------------------------------------------------------------

/** Compressed polynomial: 128 bytes (5-bit coefficients, 256/8*4). */
internal const val MLKEM_POLYCOMPRESSEDBYTES: Int = 128

/** Compressed polynomial vector: K × 320 = 640 bytes (10-bit coefficients, 256/4*5). */
internal const val MLKEM_POLYVECCOMPRESSEDBYTES: Int = MLKEM_K * 320

/** Uncompressed polynomial: 384 bytes (12-bit coefficients packed 2 per 3 bytes). */
internal const val MLKEM_POLYBYTES: Int = 384

/** Uncompressed polynomial vector: K × 384 = 768 bytes. */
internal const val MLKEM_POLYVECBYTES: Int = MLKEM_K * MLKEM_POLYBYTES

/** IND-CPA message size: 32 bytes (same as MLKEM_SYMBYTES for ML-KEM). */
internal const val MLKEM_INDCPA_MSGBYTES: Int = MLKEM_SYMBYTES

/** IND-CPA public key: POLYVECBYTES + SYMBYTES = 768 + 32 = 800 bytes. */
internal const val MLKEM_INDCPA_PUBLICKEYBYTES: Int = MLKEM_POLYVECBYTES + MLKEM_SYMBYTES

/** IND-CPA secret key: POLYVECBYTES = 768 bytes. */
internal const val MLKEM_INDCPA_SECRETKEYBYTES: Int = MLKEM_POLYVECBYTES

/** IND-CPA ciphertext: POLYVECCOMPRESSEDBYTES + POLYCOMPRESSEDBYTES = 640 + 128 = 768. */
internal const val MLKEM_INDCPA_BYTES: Int =
    MLKEM_POLYVECCOMPRESSEDBYTES + MLKEM_POLYCOMPRESSEDBYTES

/** Public key (full KEM): INDCPA_PUBLICKEYBYTES = 800 bytes. */
internal const val MLKEM_PUBLICKEYBYTES: Int = MLKEM_INDCPA_PUBLICKEYBYTES

/**
 * Secret key (full KEM): INDCPA_SECRETKEYBYTES + INDCPA_PUBLICKEYBYTES + 2*SYMBYTES = 768 + 800 +
 * 64 = 1632.
 *
 * Layout: sk_cpa(768) || pk(800) || hash_h(pk)(32) || z(32).
 */
internal const val MLKEM_SECRETKEYBYTES: Int =
    MLKEM_INDCPA_SECRETKEYBYTES + MLKEM_INDCPA_PUBLICKEYBYTES + 2 * MLKEM_SYMBYTES

/** Ciphertext (full KEM): INDCPA_BYTES = 768 bytes. */
internal const val MLKEM_CIPHERTEXTBYTES: Int = MLKEM_INDCPA_BYTES

/** Hash output size for H (SHA3-256): 32 bytes (FIPS 203, hash_h = SHA3-256). */
internal const val MLKEM_HASH_H_SIZE: Int = 32

/** Hash output size for G (SHA3-512): 64 bytes (FIPS 203, hash_g = SHA3-512). */
internal const val MLKEM_HASH_G_SIZE: Int = 64

// ------------------------------------------------------------------
// Buffer sizes for gen_matrix (ref/indcpa.c)
// ------------------------------------------------------------------
/**
 * Number of SHAKE128 blocks needed to fill one polynomial via rejection sampling. Computed as
 * ((12*N/8*(1 << 12)/Q + SHAKE128_RATE) / SHAKE128_RATE) = 3 for ML-KEM-512. Matches the Kyber
 * ref/indcpa.c `GEN_MATRIX_NBLOCKS` macro.
 */
internal const val MLKEM_GEN_MATRIX_NBLOCKS: Int = 3

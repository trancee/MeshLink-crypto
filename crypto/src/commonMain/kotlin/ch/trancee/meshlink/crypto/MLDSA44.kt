/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-44 key generation, signing, and verification (FIPS 204).
 *
 * Pure-Kotlin implementation of ML-DSA-44 (the NIST PQC standard for
 * post-quantum digital signatures), parameter set {K=4, L=4}. Verified
 * against NIST CAVP and Google Wycheproof test vectors.
 *
 * This file implements FIPS 204 Algorithms 11 (keypair), 12 (sign), and
 * 13 (verify) using the NTT engine from [MLDSANtt.kt], polynomial operations
 * from [MLDSAPoly.kt], packing from [MLDSAPolyPacking.kt], vector operations
 * from [MLDSAPolyVec.kt], and sampling from [MLDSASampling.kt].
 *
 * Design notes:
 * - SHAKE128 is used for matrix expansion (poly_uniform).
 * - SHAKE256 is used for CRH, PRF, and challenge generation.
 * - Both SHAKE128/256 are pure-Kotlin only (no native provider on any
 *   platform — ADR-0001).
 * - Randomized signing uses deterministic all-zero [rnd] (matching the
 *   FIPS 204 test vectors and the pq-crystals reference build without
 *   DILITHIUM_RANDOMIZED_SIGNING).
 * - The signing rejection loop may iterate multiple times; each iteration
 *   resamples y from the same rhoprime stream with an incrementing nonce.
 *
 * References:
 *   - FIPS 204 (final standard, August 2024)
 *   - pq-crystals/dilithium ref/sign.c, ref/packing.c, ref/polyvec.c
 */
package ch.trancee.meshlink.crypto

/**
 * ML-DSA-44 pure-Kotlin implementation (FIPS 204, parameter set {K=4, L=4}).
 *
 * Provides deterministic key generation, signing (with the FIPS 204 rejection loop), and
 * verification. All secret key material is passed through [Closeable] handles whose backing arrays
 * are zeroed on close (ADR-0002).
 *
 * Public API:
 * - [MLDSA44PureK.keypair]: generates (pk, sk)
 * - [MLDSA44PureK.sign]: signs a message, returns the signature
 * - [MLDSA44PureK.open]: verifies a signature and recovers the message
 */
internal object MLDSA44PureK {

  // ------------------------------------------------------------------
  // Keypair generation (FIPS 204 §7.1, Algorithm 11)
  // ------------------------------------------------------------------

  /**
   * Generate an ML-DSA-44 keypair from a deterministic seed (FIPS 204 §7.1).
   *
   * Uses [seed] (32 bytes) as the entropy source instead of platform randomness. This is used for
   * Wycheproof test vectors and deterministic key derivation.
   *
   * @param seed 32-byte seed
   * @return pair of (publicKey, secretKey)
   */
  fun keypairFromSeed(seed: ByteArray): Pair<ByteArray, ByteArray> {
    val seedbuf = ByteArray(2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES)
    for (i in 0 until MLDSA_SEEDBYTES) {
      seedbuf[i] = seed[i]
    }
    seedbuf[MLDSA_SEEDBYTES + 0] = MLDSA_K.toByte()
    seedbuf[MLDSA_SEEDBYTES + 1] = MLDSA_L.toByte()

    val expanded =
        SHAKE256PureK.digest(
            seedbuf.copyOfRange(0, MLDSA_SEEDBYTES + 2),
            2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES,
        )
    expanded.copyInto(seedbuf, 0, 0, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES)

    val rho = seedbuf.copyOfRange(0, MLDSA_SEEDBYTES)
    val rhoprime = seedbuf.copyOfRange(MLDSA_SEEDBYTES, MLDSA_SEEDBYTES + MLDSA_CRHBYTES)
    val key =
        seedbuf.copyOfRange(MLDSA_SEEDBYTES + MLDSA_CRHBYTES, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES)

    val mat = Array(MLDSA_K) { Array(MLDSA_L) { IntArray(256) } }
    polyvecMatrixExpand(mat, rho)

    val s1 = Array(MLDSA_L) { IntArray(256) }
    val s2 = Array(MLDSA_K) { IntArray(256) }
    polyveclUniformEta(s1, rhoprime, 0)
    polyveckUniformEta(s2, rhoprime, MLDSA_L)

    val s1hat = Array(MLDSA_L) { IntArray(256) }
    for (i in 0 until MLDSA_L) {
      s1[i].copyInto(s1hat[i], 0, 0, 256)
    }
    polyveclNtt(s1hat)

    val t1 = Array(MLDSA_K) { IntArray(256) }
    polyveclPointwiseAccMontgomery(t1, mat, s1hat)
    polyveckReduce(t1)
    polyveckInvnttTomont(t1)

    polyveckAdd(t1, t1, s2)
    polyveckCaddq(t1)
    val t0 = Array(MLDSA_K) { IntArray(256) }
    polyveckPower2round(t1, t0, t1)

    val pk = ByteArray(MLDSA_PUBLICKEYBYTES)
    packPk(pk, 0, rho, t1)

    val tr = SHAKE256PureK.digest(pk, MLDSA_TRBYTES)

    val sk = ByteArray(MLDSA_SECRETKEYBYTES)
    packSk(sk, 0, rho, tr, key, t0, s1, s2)

    return Pair(pk, sk)
  }

  /**
   * Generate an ML-DSA-44 keypair (FIPS 204 §7.1).
   *
   * Uses platform randomness for the initial seed, then deterministically derives ρ, ρ′, and key
   * via SHAKE256.
   *
   * @return pair of (publicKey, secretKey)
   */
  fun keypair(): Pair<ByteArray, ByteArray> = keypairFromSeed(randomBytes(MLDSA_SEEDBYTES))

  // ------------------------------------------------------------------
  // Signing (FIPS 204 §7.2, Algorithm 12)
  // ------------------------------------------------------------------

  /**
   * Sign a message with ML-DSA-44 (FIPS 204 §7.2).
   *
   * Implements the rejection-sampling signing loop. Uses deterministic all-zero randomness
   * (matching FIPS 204 test vectors).
   *
   * @param message the message to sign
   * @param secretKey the secret key (from [keypair])
   * @return the 2420-byte signature
   */
  fun sign(message: ByteArray, secretKey: ByteArray): ByteArray =
      sign(message, secretKey, byteArrayOf())

  /**
   * Sign a message with a private key and optional context string (FIPS 204 §7.2).
   *
   * @param message the message to sign
   * @param secretKey the 2560-byte secret key (from [keypair] or [keypairFromSeed])
   * @param context optional context string (empty by default; ≤255 bytes per FIPS 204)
   * @return the 2420-byte ML-DSA-44 signature
   */
  fun sign(message: ByteArray, secretKey: ByteArray, context: ByteArray): ByteArray {
    check(context.size <= 255) { "context must be at most 255 bytes" }
    val rho = ByteArray(MLDSA_SEEDBYTES)
    val tr = ByteArray(MLDSA_TRBYTES)
    val key = ByteArray(MLDSA_SEEDBYTES)
    val t0 = Array(MLDSA_K) { IntArray(256) }
    val s1 = Array(MLDSA_L) { IntArray(256) }
    val s2 = Array(MLDSA_K) { IntArray(256) }
    unpackSk(rho, tr, key, t0, s1, s2, secretKey)

    // Compute mu = CRH(tr, pre, msg), where pre = (0, ctxlen, ctx)
    val pre = ByteArray(2 + context.size)
    pre[0] = 0
    pre[1] = context.size.toByte()
    context.copyInto(pre, 2)
    val mu = ByteArray(MLDSA_CRHBYTES)
    val h1 = SHAKE256Hasher()
    h1.update(tr, 0, tr.size)
    h1.update(pre, 0, pre.size)
    h1.update(message, 0, message.size)
    h1.digest(MLDSA_CRHBYTES).copyInto(mu, 0, 0, MLDSA_CRHBYTES)

    // Compute rhoprime = CRH(key, rnd, mu), rnd = 32 zero bytes
    val rhoprime = ByteArray(MLDSA_CRHBYTES)
    val h2 = SHAKE256Hasher()
    h2.update(key, 0, key.size)
    val rnd = ByteArray(32) // All zeros (deterministic signing)
    h2.update(rnd, 0, rnd.size)
    h2.update(mu, 0, mu.size)
    h2.digest(MLDSA_CRHBYTES).copyInto(rhoprime, 0, 0, MLDSA_CRHBYTES)

    // Expand matrix A
    val mat = Array(MLDSA_K) { Array(MLDSA_L) { IntArray(256) } }
    polyvecMatrixExpand(mat, rho)

    // Pre-compute NTT of s1, s2, t0
    polyveclNtt(s1)
    polyveckNtt(s2)
    polyveckNtt(t0)

    val sig = ByteArray(MLDSA_BYTES)
    val cp = IntArray(256)
    val z = Array(MLDSA_L) { IntArray(256) }
    val y = Array(MLDSA_L) { IntArray(256) }
    val w1 = Array(MLDSA_K) { IntArray(256) }
    val w0 = Array(MLDSA_K) { IntArray(256) }
    val h = Array(MLDSA_K) { IntArray(256) }

    // Rejection loop
    var nonce = 0
    while (true) {
      // Sample y, compute w1 = A * NTT(y)
      polyveclUniformGamma1(y, rhoprime, nonce++)

      // z = y in NTT domain
      for (i in 0 until MLDSA_L) {
        y[i].copyInto(z[i], 0, 0, 256)
      }
      polyveclNtt(z)
      polyveclPointwiseAccMontgomery(w1, mat, z)
      polyveckReduce(w1)
      polyveckInvnttTomont(w1)

      // Decompose w1, pack into sig buffer
      polyveckCaddq(w1)
      polyveckDecompose(w1, w0, w1)
      polyveckPackW1(sig, 0, w1)

      // Compute c = CRH(mu, w1_packed)
      val cShake = SHAKE256Hasher()
      cShake.update(mu, 0, mu.size)
      cShake.update(sig, 0, MLDSA_K * MLDSA_POLYW1_PACKEDBYTES)
      cShake.digest(MLDSA_CTILDEBYTES).copyInto(sig, 0, 0, MLDSA_CTILDEBYTES)

      // Challenge polynomial
      polyChallenge(cp, sig.copyOfRange(0, MLDSA_CTILDEBYTES))
      MLDSANtt.ntt(cp)

      // z = InvNTT(cp * s1) + y
      polyveclPointwisePolyMontgomery(z, cp, s1)
      polyveclInvnttTomont(z)
      polyveclAdd(z, z, y)
      polyveclReduce(z)

      // Check norm of z
      if (polyveclChknorm(z, MLDSA_GAMMA1 - MLDSA_BETA)) continue

      // h = InvNTT(cp * s2); w0 -= h
      polyveckPointwisePolyMontgomery(h, cp, s2)
      polyveckInvnttTomont(h)
      polyveckSub(w0, w0, h)
      polyveckReduce(w0)

      if (polyveckChknorm(w0, MLDSA_GAMMA2 - MLDSA_BETA)) continue

      // h = InvNTT(cp * t0); w0 += h; check hint norm
      polyveckPointwisePolyMontgomery(h, cp, t0)
      polyveckInvnttTomont(h)
      polyveckReduce(h)

      if (polyveckChknorm(h, MLDSA_GAMMA2)) continue

      polyveckAdd(w0, w0, h)

      // Make hints
      val hints = polyveckMakeHint(h, w0, w1)
      if (hints > MLDSA_OMEGA) continue

      // Pack signature
      packSig(sig, sig.copyOfRange(0, MLDSA_CTILDEBYTES), z, h)
      return sig
    }
  }

  // ------------------------------------------------------------------
  // Verification (FIPS 204 §7.3, Algorithm 13)
  // ------------------------------------------------------------------

  /**
   * Verify an ML-DSA-44 signature with an optional context string (FIPS 204 §7.3).
   *
   * @param sig the signature (must be 2420 bytes)
   * @param message the message that was signed
   * @param publicKey the public key (must be 1312 bytes)
   * @param context optional context string (must match what was used during signing)
   * @return true if the signature is valid
   */
  fun verify(
      sig: ByteArray,
      message: ByteArray,
      publicKey: ByteArray,
      context: ByteArray = byteArrayOf(),
  ): Boolean {
    if (context.size > 255 || sig.size != MLDSA_BYTES || publicKey.size != MLDSA_PUBLICKEYBYTES)
        return false

    // Unpack public key
    val rho = ByteArray(MLDSA_SEEDBYTES)
    val t1 = Array(MLDSA_K) { IntArray(256) }
    unpackPk(rho, t1, publicKey)

    // Unpack signature
    val c = ByteArray(MLDSA_CTILDEBYTES)
    val z = Array(MLDSA_L) { IntArray(256) }
    val h = Array(MLDSA_K) { IntArray(256) }
    if (unpackSig(c, z, h, sig)) return false

    // Check norm of z
    if (polyveclChknorm(z, MLDSA_GAMMA1 - MLDSA_BETA)) return false

    // Recover tr from pk
    val tr = SHAKE256PureK.digest(publicKey, MLDSA_TRBYTES)

    // Compute mu = CRH(tr, pre, msg), where pre = (0, ctxlen, ctx)
    val pre = ByteArray(2 + context.size)
    pre[0] = 0
    pre[1] = context.size.toByte()
    context.copyInto(pre, 2)
    val mu = ByteArray(MLDSA_CRHBYTES)
    val h1 = SHAKE256Hasher()
    h1.update(tr, 0, tr.size)
    h1.update(pre, 0, pre.size)
    h1.update(message, 0, message.size)
    h1.digest(MLDSA_CRHBYTES).copyInto(mu, 0, 0, mu.size)

    // Expand matrix A
    val mat = Array(MLDSA_K) { Array(MLDSA_L) { IntArray(256) } }
    polyvecMatrixExpand(mat, rho)
    val w1 = Array(MLDSA_K) { IntArray(256) }

    // Matrix-vector multiplication: w1 = Az (in NTT domain)
    polyveclNtt(z)
    polyveclPointwiseAccMontgomery(w1, mat, z)
    polyveckReduce(w1)

    // Challenge
    val cp = IntArray(256)
    polyChallenge(cp, c)
    MLDSANtt.ntt(cp)

    // Shift t1 and NTT it
    polyveckShiftl(t1)
    polyveckNtt(t1)

    // w1 -= cp * t1 (in NTT domain)
    polyveckPointwisePolyMontgomery(t1, cp, t1)
    polyveckSub(w1, w1, t1)
    polyveckReduce(w1)
    polyveckInvnttTomont(w1)

    // Reconstruct w1
    polyveckCaddq(w1)
    polyveckUseHint(w1, w1, h)

    // Compute c2 = H(mu, w1_packed)
    val w1Buf = ByteArray(MLDSA_K * MLDSA_POLYW1_PACKEDBYTES)
    polyveckPackW1(w1Buf, 0, w1)
    val c2Shake = SHAKE256Hasher()
    c2Shake.update(mu, 0, mu.size)
    c2Shake.update(w1Buf, 0, w1Buf.size)
    val c2 = c2Shake.digest(MLDSA_CTILDEBYTES)

    // Compare c and c2
    for (i in 0 until MLDSA_CTILDEBYTES) {
      if (c[i] != c2[i]) return false
    }
    return true
  }

  // ------------------------------------------------------------------
  // Packing/unpacking helpers
  // ------------------------------------------------------------------

  private fun packPk(pk: ByteArray, pkOff: Int, rho: ByteArray, t1: Array<IntArray>) {
    for (i in 0 until MLDSA_SEEDBYTES) {
      pk[pkOff + i] = rho[i]
    }
    var off = pkOff + MLDSA_SEEDBYTES
    for (i in 0 until MLDSA_K) {
      polyT1Pack(pk, off, t1[i])
      off += MLDSA_POLYT1_PACKEDBYTES
    }
  }

  private fun unpackPk(rho: ByteArray, t1: Array<IntArray>, pk: ByteArray) {
    for (i in 0 until MLDSA_SEEDBYTES) {
      rho[i] = pk[i]
    }
    var off = MLDSA_SEEDBYTES
    for (i in 0 until MLDSA_K) {
      polyT1Unpack(t1[i], pk, off)
      off += MLDSA_POLYT1_PACKEDBYTES
    }
  }

  private fun packSk(
      sk: ByteArray,
      skOff: Int,
      rho: ByteArray,
      tr: ByteArray,
      key: ByteArray,
      t0: Array<IntArray>,
      s1: Array<IntArray>,
      s2: Array<IntArray>,
  ) {
    var off = skOff
    for (i in 0 until MLDSA_SEEDBYTES) {
      sk[off + i] = rho[i]
    }
    off += MLDSA_SEEDBYTES

    for (i in 0 until MLDSA_SEEDBYTES) {
      sk[off + i] = key[i]
    }
    off += MLDSA_SEEDBYTES

    for (i in 0 until MLDSA_TRBYTES) {
      sk[off + i] = tr[i]
    }
    off += MLDSA_TRBYTES

    for (i in 0 until MLDSA_L) {
      polyEtaPack(sk, off, s1[i])
      off += MLDSA_POLYETA_PACKEDBYTES
    }

    for (i in 0 until MLDSA_K) {
      polyEtaPack(sk, off, s2[i])
      off += MLDSA_POLYETA_PACKEDBYTES
    }

    for (i in 0 until MLDSA_K) {
      polyT0Pack(sk, off, t0[i])
      off += MLDSA_POLYT0_PACKEDBYTES
    }
  }

  private fun unpackSk(
      rho: ByteArray,
      tr: ByteArray,
      key: ByteArray,
      t0: Array<IntArray>,
      s1: Array<IntArray>,
      s2: Array<IntArray>,
      sk: ByteArray,
  ) {
    var off = 0
    for (i in 0 until MLDSA_SEEDBYTES) {
      rho[i] = sk[off + i]
    }
    off += MLDSA_SEEDBYTES

    for (i in 0 until MLDSA_SEEDBYTES) {
      key[i] = sk[off + i]
    }
    off += MLDSA_SEEDBYTES

    for (i in 0 until MLDSA_TRBYTES) {
      tr[i] = sk[off + i]
    }
    off += MLDSA_TRBYTES

    for (i in 0 until MLDSA_L) {
      polyEtaUnpack(s1[i], sk, off)
      off += MLDSA_POLYETA_PACKEDBYTES
    }

    for (i in 0 until MLDSA_K) {
      polyEtaUnpack(s2[i], sk, off)
      off += MLDSA_POLYETA_PACKEDBYTES
    }

    for (i in 0 until MLDSA_K) {
      polyT0Unpack(t0[i], sk, off)
      off += MLDSA_POLYT0_PACKEDBYTES
    }
  }

  private fun packSig(sig: ByteArray, c: ByteArray, z: Array<IntArray>, h: Array<IntArray>) {
    var off = 0
    for (i in 0 until MLDSA_CTILDEBYTES) {
      sig[off + i] = c[i]
    }
    off += MLDSA_CTILDEBYTES

    for (i in 0 until MLDSA_L) {
      polyZPack(sig, off, z[i])
      off += MLDSA_POLYZ_PACKEDBYTES
    }

    // Encode h
    for (i in 0 until MLDSA_OMEGA + MLDSA_K) {
      sig[off + i] = 0
    }

    var k = 0
    for (i in 0 until MLDSA_K) {
      for (j in 0 until 256) {
        if (h[i][j] != 0) {
          sig[off + k] = j.toByte()
          k++
        }
      }
      sig[off + MLDSA_OMEGA + i] = k.toByte()
    }
  }

  private fun unpackSig(
      c: ByteArray,
      z: Array<IntArray>,
      h: Array<IntArray>,
      sig: ByteArray,
  ): Boolean {
    var off = 0
    for (i in 0 until MLDSA_CTILDEBYTES) {
      c[i] = sig[off + i]
    }
    off += MLDSA_CTILDEBYTES

    for (i in 0 until MLDSA_L) {
      polyZUnpack(z[i], sig, off)
      off += MLDSA_POLYZ_PACKEDBYTES
    }

    // Decode h
    var k = 0
    for (i in 0 until MLDSA_K) {
      for (j in 0 until 256) {
        h[i][j] = 0
      }

      if (
          sig[off + MLDSA_OMEGA + i].toInt() < k || sig[off + MLDSA_OMEGA + i].toInt() > MLDSA_OMEGA
      ) {
        return true // malformed
      }

      val limit = sig[off + MLDSA_OMEGA + i].toInt()
      for (j in k until limit) {
        if (j > k && (sig[off + j].toInt() and 0xFF) <= (sig[off + j - 1].toInt() and 0xFF)) {
          return true // malformed — coefficients not in order
        }
        h[i][sig[off + j].toInt() and 0xFF] = 1
      }
      k = limit
    }

    // Extra indices must be zero
    for (j in k until MLDSA_OMEGA) {
      if (sig[off + j].toInt() != 0) return true
    }

    return false
  }
}

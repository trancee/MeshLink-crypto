/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 IND-CPA scheme (FIPS 203 §6.2 Algorithm 4–12, ref/indcpa.c).
 *
 * Pure-Kotlin implementation of the CPA-secure public-key encryption underlying
 * ML-KEM: key generation (indcpa_keypair_derand), encryption (indcpa_enc),
 * decryption (indcpa_dec), deterministic matrix generation (gen_matrix), and
 * uniform rejection sampling (rej_uniform).
 *
 * Matrix generation uses SHAKE128 as the XOF (FIPS 203). The G function uses
 * SHA3-512 and H uses SHA3-256 — see MLKEM512.kt for the CCA wrapper that calls
 * hash_g and hash_h.
 *
 * Reference: pq-crystals/kyber ref/indcpa.c, ref/symmetric.h
 */
package ch.trancee.meshlink.crypto

// ------------------------------------------------------------------
// Rejection sampling (ref/indcpa.c `rej_uniform`)
// ------------------------------------------------------------------

/**
 * Rejection-sample 12-bit integers mod Q = 3329 from a byte buffer.
 *
 * Each 3-byte group yields two 12-bit values; those < Q are accepted. Returns the number of
 * accepted values (at most [len]).
 *
 * The acceptance check `val < Q` is data-independent in timing (the branch depends on public byte
 * values from the XOF, not on secret data — ADR-0003).
 *
 * @param r output coefficient array (at least [len] elements)
 * @param len number of coefficients requested (typically KYBER_N = 256)
 * @param buf input buffer of uniform random bytes
 * @param buflen length of [buf]
 * @return number of coefficients actually written to [r]
 */
internal fun rejUniform(r: IntArray, len: Int, buf: ByteArray, buflen: Int, outOff: Int = 0): Int {
  var ctr = outOff
  var pos = 0
  while (ctr < len && pos + 3 <= buflen) {
    val val0 = ((buf[pos].toInt() and 0xFF) or ((buf[pos + 1].toInt() and 0xFF) shl 8)) and 0xFFF
    val val1 =
        (((buf[pos + 1].toInt() and 0xFF) ushr 4) or ((buf[pos + 2].toInt() and 0xFF) shl 4)) and
            0xFFF
    pos += 3

    if (val0 < MLKEM_Q) {
      r[ctr] = val0
      ctr++
    }
    if (ctr < len && val1 < MLKEM_Q) {
      r[ctr] = val1
      ctr++
    }
  }
  return ctr
}

// ------------------------------------------------------------------
// Matrix generation (ref/indcpa.c `gen_matrix`)
// ------------------------------------------------------------------

/**
 * Absorb a 32-byte seed and two coordinate bytes into SHAKE128, matching Kyber's `xof_absorb`
 * (ref/symmetric.c `kyber_shake128_absorb`).
 *
 * Produces `SHAKE128(seed || x || y)` output of [outputLength] bytes.
 *
 * @param seed 32-byte public seed
 * @param x row coordinate
 * @param y column coordinate
 * @param outputLength number of output bytes to squeeze
 * @return [outputLength] bytes of SHAKE128 output
 */
private fun xofAbsorb(
    seed: ByteArray,
    x: Int,
    y: Int,
    outputLength: Int,
): ByteArray {
  val msg = ByteArray(MLKEM_SYMBYTES + 2)
  seed.copyInto(msg, 0, 0, MLKEM_SYMBYTES)
  msg[MLKEM_SYMBYTES] = x.toByte()
  msg[MLKEM_SYMBYTES + 1] = y.toByte()
  return SHAKE128PureK.digest(msg, outputLength)
}

/**
 * Deterministically generate the K × K NTT matrix A (or A^T) from a seed (ref/indcpa.c
 * `gen_matrix`).
 *
 * Each polynomial entry is sampled via [rejUniform] from SHAKE128 output. The XOF domain is `seed
 * || x || y` where (x, y) is chosen per entry:
 * - If [transposed]: entries are indexed as (row, col) = (i, j)
 * - If not transposed: entries are indexed as (col, row) = (j, i)
 *
 * Initial squeeze: `GEN_MATRIX_NBLOCKS * SHAKE128_RATE` bytes = 504 bytes. If rejection sampling
 * yields fewer than 256 coefficients, additional 168-byte blocks are squeezed until the polynomial
 * is full.
 *
 * @param a output K×K matrix stored as `Array<Array<IntArray>>` where `a[i][j]` is the polynomial
 *   at row i, column j
 * @param seed 32-byte public seed
 * @param transposed if true, generate A^T; otherwise generate A
 */
internal fun genMatrix(
    a: Array<Array<IntArray>>,
    seed: ByteArray,
    transposed: Boolean,
) {
  for (i in 0 until MLKEM_K) {
    for (j in 0 until MLKEM_K) {
      val x = if (transposed) i else j
      val y = if (transposed) j else i

      val bufSize = 5 * SHAKE128_RATE
      val buf = xofAbsorb(seed, x, y, bufSize)
      var ctr = rejUniform(a[i][j], MLKEM_N, buf, bufSize)

      var extraPos = 0
      while (ctr < MLKEM_N) {
        if (extraPos + 3 > SHAKE128_RATE) {
          extraPos = 0
        }
        val extMsg = ByteArray(MLKEM_SYMBYTES + 3)
        seed.copyInto(extMsg, 0, 0, MLKEM_SYMBYTES)
        extMsg[MLKEM_SYMBYTES] = x.toByte()
        extMsg[MLKEM_SYMBYTES + 1] = y.toByte()
        extMsg[MLKEM_SYMBYTES + 2] = 0xFF.toByte()
        val extraBuf = SHAKE128PureK.digest(extMsg, SHAKE128_RATE)
        ctr = rejUniform(a[i][j], MLKEM_N, extraBuf, SHAKE128_RATE, outOff = ctr)
        extraPos += 3
      }
    }
  }
}

// ------------------------------------------------------------------
// IND-CPA key generation (ref/indcpa.c `indcpa_keypair_derand`)
// ------------------------------------------------------------------

/** Serialize the public key: `pk = polyvec_tobytes(pkpv) || seed` (ref/indcpa.c `pack_pk`). */
private fun packPk(r: ByteArray, rOff: Int, pkpv: Array<IntArray>, seed: ByteArray) {
  polyvecTobytes(r, rOff, pkpv)
  seed.copyInto(r, rOff + MLKEM_POLYVECBYTES, 0, MLKEM_SYMBYTES)
}

/**
 * Deserialize the public key: `pkpv = polyvec_frombytes(pk)`, `seed = pk[768:800]` (ref/indcpa.c
 * `unpack_pk`).
 */
private fun unpackPk(
    pkpv: Array<IntArray>,
    seed: ByteArray,
    packedpk: ByteArray,
    packedpkOff: Int,
) {
  for (i in 0 until MLKEM_K) {
    pkpv[i] = IntArray(MLKEM_N)
  }
  polyvecFrombytes(pkpv, packedpk, packedpkOff)
  val seedOff = packedpkOff + MLKEM_POLYVECBYTES
  for (i in 0 until MLKEM_SYMBYTES) {
    seed[i] = packedpk[seedOff + i]
  }
}

/** Serialize the secret key: `sk = polyvec_tobytes(skpv)` (ref/indcpa.c `pack_sk`). */
private fun packSk(r: ByteArray, rOff: Int, skpv: Array<IntArray>) {
  polyvecTobytes(r, rOff, skpv)
}

/** Deserialize the secret key: `skpv = polyvec_frombytes(sk)` (ref/indcpa.c `unpack_sk`). */
private fun unpackSk(skpv: Array<IntArray>, packedsk: ByteArray, packedskOff: Int) {
  for (i in 0 until MLKEM_K) {
    skpv[i] = IntArray(MLKEM_N)
  }
  polyvecFrombytes(skpv, packedsk, packedskOff)
}

/**
 * Serialize ciphertext: `c = polyvec_compress(b) || poly_compress(v)` (ref/indcpa.c
 * `pack_ciphertext`).
 */
private fun packCiphertext(r: ByteArray, rOff: Int, b: Array<IntArray>, v: IntArray) {
  polyvecCompress(r, rOff, b)
  polyCompress(r, rOff + MLKEM_POLYVECCOMPRESSEDBYTES, v)
}

/**
 * Deserialize ciphertext: `b = polyvec_decompress(c)`, `v = poly_decompress(c+640)` (ref/indcpa.c
 * `unpack_ciphertext`).
 */
private fun unpackCiphertext(
    b: Array<IntArray>,
    v: IntArray,
    c: ByteArray,
    cOff: Int,
) {
  for (i in 0 until MLKEM_K) {
    b[i] = IntArray(MLKEM_N)
  }
  polyvecDecompress(b, c, cOff)
  polyDecompress(v, c, cOff + MLKEM_POLYVECCOMPRESSEDBYTES)
}

/**
 * IND-CPA keypair generation (FIPS 203 §6.2 Algorithm 5, ref/indcpa.c `indcpa_keypair_derand`).
 *
 * Given 32 bytes of randomness [coins], derives a public seed and noise seed via SHA3-512 (the G
 * function), generates matrix A from the public seed, samples the secret vector and error vector
 * via SHAKE256 PRF, performs NTT-domain matrix-vector multiplication, and serializes the result.
 *
 * @param pk output public key (800 bytes, written from [pkOff])
 * @param pkOff offset into [pk]
 * @param sk output secret key (768 bytes, written from [skOff])
 * @param skOff offset into [sk]
 * @param coins 32 bytes of randomness (used for both ρ derivation and noise seed)
 */
internal fun indcpaKeypairDerand(
    pk: ByteArray,
    pkOff: Int,
    sk: ByteArray,
    skOff: Int,
    coins: ByteArray,
    coinsOff: Int = 0,
) {
  val buf = ByteArray(2 * MLKEM_SYMBYTES)
  coins.copyInto(buf, 0, 0, MLKEM_SYMBYTES)
  buf[MLKEM_SYMBYTES] = MLKEM_K.toByte()
  val gOut = SHA3_512Hasher().also { it.update(buf, 0, MLKEM_SYMBYTES + 1) }.digest()
  val publicSeed = gOut.copyOfRange(0, MLKEM_SYMBYTES)
  val noiseSeed = gOut.copyOfRange(MLKEM_SYMBYTES, 2 * MLKEM_SYMBYTES)

  // Allocate polynomial vectors
  val a = Array(MLKEM_K) { Array(MLKEM_K) { IntArray(MLKEM_N) } }
  val skpv = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val e = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val pkpv = Array(MLKEM_K) { IntArray(MLKEM_N) }

  genMatrix(a, publicSeed, transposed = false)
  // Sample noise (nonce starts at 0, increments)
  var nonce = 0
  for (i in 0 until MLKEM_K) {
    polyGetnoiseEta1(skpv[i], noiseSeed, 0, nonce)
    nonce++
  }
  for (i in 0 until MLKEM_K) {
    polyGetnoiseEta1(e[i], noiseSeed, 0, nonce)
    nonce++
  }

  // NTT of secret and error vectors

  // NTT of secret and error vectors
  polyvecNtt(skpv)
  polyvecNtt(e)

  // Matrix-vector multiplication: pkpv = A * skpv (mod M, with Montgomery)
  for (i in 0 until MLKEM_K) {
    polyvecBasemulAccMontgomery(pkpv[i], a[i], skpv)
    polyTomont(pkpv[i])
  }

  // Add error and reduce
  polyvecAdd(pkpv, pkpv, e)
  polyvecReduce(pkpv)
  // Serialize
  packSk(sk, skOff, skpv)
  packPk(pk, pkOff, pkpv, publicSeed)
}

// ------------------------------------------------------------------
// IND-CPA encryption (ref/indcpa.c `indcpa_enc`)
// ------------------------------------------------------------------

/**
 * IND-CPA encryption (FIPS 203 §6.2 Algorithm 12, ref/indcpa.c `indcpa_enc`).
 *
 * Encrypts message [m] using public key [pk] and random coins [coins]. The message is encoded as a
 * polynomial, the matrix transpose A^T is generated from the public seed, the secret vector is
 * NTT-transformed, and the ciphertext is computed as (b, v) where `b = A^T · sp + ep` and `v = pk ·
 * sp + epp + k`.
 *
 * @param c output ciphertext (768 bytes, written from [cOff])
 * @param cOff offset into [c]
 * @param m 32-byte message to encrypt
 * @param mOff offset into [m]
 * @param pk 800-byte public key
 * @param pkOff offset into [pk]
 * @param coins 32 bytes of randomness
 */
internal fun indcpaEncrypt(
    c: ByteArray,
    cOff: Int,
    m: ByteArray,
    mOff: Int,
    pk: ByteArray,
    pkOff: Int,
    coins: ByteArray,
    coinsOff: Int = 0,
) {
  val seed = ByteArray(MLKEM_SYMBYTES)
  val pkpv = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val sp = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val ep = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val at = Array(MLKEM_K) { Array(MLKEM_K) { IntArray(MLKEM_N) } }
  val b = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val v = IntArray(MLKEM_N)
  val k = IntArray(MLKEM_N)
  val epp = IntArray(MLKEM_N)

  // Unpack public key: pkpv = decode(pk[:768]), seed = pk[768:800]
  unpackPk(pkpv, seed, pk, pkOff)

  // Encode message as polynomial
  polyFrommsg(k, m, mOff)

  // Generate transpose of matrix A
  genMatrix(at, seed, transposed = true)
  // Sample noise
  var nonce = 0
  for (i in 0 until MLKEM_K) {
    polyGetnoiseEta1(sp[i], coins, coinsOff, nonce)
    nonce++
  }
  for (i in 0 until MLKEM_K) {
    polyGetnoiseEta2(ep[i], coins, coinsOff, nonce)
    nonce++
  }
  polyGetnoiseEta2(epp, coins, coinsOff, nonce)

  // NTT of secret vector sp
  polyvecNtt(sp)

  // Matrix-vector multiplication: b[i] = sum_j at[i][j] * sp[j]
  for (i in 0 until MLKEM_K) {
    polyvecBasemulAccMontgomery(b[i], at[i], sp)
  }

  // Inner product: v = sum_j pkpv[j] * sp[j]
  polyvecBasemulAccMontgomery(v, pkpv, sp)

  // Inverse NTT
  polyvecInvnttTomont(b)
  polyInvnttTomont(v)

  // Add error terms and message
  polyvecAdd(b, b, ep)
  MLKEMNtt.polyAdd(v, v, epp)
  MLKEMNtt.polyAdd(v, v, k)
  polyvecReduce(b)
  MLKEMNtt.polyReduce(v)

  // Serialize ciphertext
  packCiphertext(c, cOff, b, v)
}

// ------------------------------------------------------------------
// IND-CPA decryption (ref/indcpa.c `indcpa_dec`)
// ------------------------------------------------------------------

/**
 * IND-CPA decryption (FIPS 203 §6.2, ref/indcpa.c `indcpa_dec`).
 *
 * Unpacks ciphertext, computes `mp = skpv · b` in NTT domain, applies inverse NTT, subtracts from v
 * (i.e., computes v - mp), and recovers the message via [polyTomsg].
 *
 * @param m output 32-byte decrypted message
 * @param mOff offset into [m]
 * @param c ciphertext (768 bytes)
 * @param cOff offset into [c]
 * @param sk 768-byte secret key (IND-CPA secret, not the full CCA key)
 * @param skOff offset into [sk]
 */
internal fun indcpaDecrypt(
    m: ByteArray,
    mOff: Int,
    c: ByteArray,
    cOff: Int,
    sk: ByteArray,
    skOff: Int,
) {
  val b = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val skpv = Array(MLKEM_K) { IntArray(MLKEM_N) }
  val v = IntArray(MLKEM_N)
  val mp = IntArray(MLKEM_N)

  unpackCiphertext(b, v, c, cOff)
  unpackSk(skpv, sk, skOff)

  polyvecNtt(b)
  polyvecBasemulAccMontgomery(mp, skpv, b)
  polyInvnttTomont(mp)

  // mp = v - mp  (ref/indcpa.c poly_sub(&mp, &v, &mp))
  MLKEMNtt.polySub(mp, v, mp)
  MLKEMNtt.polyReduce(mp)

  polyTomsg(m, mOff, mp)
}

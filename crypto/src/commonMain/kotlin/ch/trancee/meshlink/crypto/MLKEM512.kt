/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 CCA-secure KEM (FIPS 203 §7, Algorithms 16–18, ref/kem.c).
 *
 * Pure-Kotlin implementation of the full KEM: key generation (KeyGen),
 * encapsulation (Encaps), and decapsulation (Decaps) with the Fujisaki-Okamoto
 * transform and implicit rejection.
 *
 * Hash function mapping (FIPS 203 §4.2):
 * - G  = SHA3-512 — key derivation in KeyGen and FO transform
 * - H  = SHA3-256 — hash of public key, ciphertext integrity check
 * - J  = SHAKE256(., 32) — implicit rejection key
 * - XOF = SHAKE128 — matrix generation, noise sampling (in MLKEMCbd / MLKEMIndCpa)
 * - PRF = SHAKE256 — noise generation (in MLKEMPoly)
 *
 * Secret-key layout (FIPS 203 §3.1):
 *   sk = sk_cpa (768B) || pk (800B) || H(pk) (32B) || z (32B) = 1632B
 *
 * Reference: pq-crystals/kyber standard/ref/kem.c
 *            FIPS 203 §7 (ML-KEM)
 */
package ch.trancee.meshlink.crypto

// ------------------------------------------------------------------
// Internal helpers
// ------------------------------------------------------------------

/**
 * Implicit rejection key derivation: `J(z || c) = SHAKE256(z || c, 32)` (FIPS 203 §4.2, ref/kem.c
 * `rkprf`).
 *
 * Used in decapsulation when the re-encrypted ciphertext does not match. Produces a pseudo-random
 * shared secret that is uncorrelated with the true key, preventing an attacker from learning
 * anything useful via decapsulation oracles.
 *
 * @param z 32-byte implicit rejection secret
 * @param zOff offset into [z]
 * @param c ciphertext (768 bytes)
 * @param cOff offset into [c]
 * @return 32-byte pseudo-random shared secret
 */
internal fun rkprf(z: ByteArray, zOff: Int, c: ByteArray, cOff: Int): ByteArray {
  val msg = ByteArray(MLKEM_SYMBYTES + MLKEM_CIPHERTEXTBYTES)
  z.copyInto(msg, 0, zOff, zOff + MLKEM_SYMBYTES)
  c.copyInto(msg, MLKEM_SYMBYTES, cOff, cOff + MLKEM_CIPHERTEXTBYTES)
  return SHAKE256PureK.digest(msg, MLKEM_SSBYTES)
}

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------

/**
 * ML-KEM-512 key encapsulation mechanism (FIPS 203 §7, Algorithm 16–18).
 *
 * Key generation, encapsulation, and decapsulation using the CCA-secure Fujisaki-Okamoto transform
 * with implicit rejection.
 */
public object MLKEM512 {

  /** Size of the public/encapsulation key in bytes: 800 (FIPS 203, Table 3). */
  public const val PUBLIC_KEY_BYTES: Int = MLKEM_PUBLICKEYBYTES

  /** Size of the secret/decapsulation key in bytes: 1632 (FIPS 203, Table 3). */
  public const val SECRET_KEY_BYTES: Int = MLKEM_SECRETKEYBYTES

  /** Size of the ciphertext in bytes: 768 (FIPS 203, Table 3). */
  public const val CIPHERTEXT_BYTES: Int = MLKEM_CIPHERTEXTBYTES

  /** Size of the shared secret in bytes: 32. */
  public const val SHARED_SECRET_BYTES: Int = MLKEM_SSBYTES

  /**
   * Generates an ML-KEM-512 key pair (FIPS 203 §7, Algorithm 16).
   *
   * Uses the provided 64 bytes of randomness [coins]: the first 32 bytes seed the CPA key
   * generation (via G = SHA3-512 to derive the public seed and noise seed), and the remaining 32
   * bytes become the implicit rejection value z.
   *
   * @param coins 64 bytes of cryptographically secure randomness (2 × 32)
   * @return a pair of (publicKey, secretKey) byte arrays
   */
  public fun keyPair(coins: ByteArray): Result<Pair<ByteArray, ByteArray>> = runCatching {
    require(coins.size == 2 * MLKEM_SYMBYTES) {
      "coins must be ${2 * MLKEM_SYMBYTES} bytes, got ${coins.size}"
    }

    val pk = ByteArray(MLKEM_PUBLICKEYBYTES)
    val sk = ByteArray(MLKEM_SECRETKEYBYTES)

    // CPA keypair: derives pk and sk_cpa from coins[:32]
    indcpaKeypairDerand(pk, 0, sk, 0, coins)

    // Full secret key = sk_cpa || pk || H(pk) || z
    // Copy pk into sk after the CPA secret key
    pk.copyInto(sk, MLKEM_INDCPA_SECRETKEYBYTES, 0, MLKEM_PUBLICKEYBYTES)

    // H(pk) = SHA3-256(pk)
    SHA3_256PureK.digest(pk)
        .copyInto(
            sk,
            MLKEM_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES,
            0,
            MLKEM_SYMBYTES,
        )

    // z = coins[32:64] (implicit rejection secret)
    coins.copyInto(sk, MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES, MLKEM_SYMBYTES, 2 * MLKEM_SYMBYTES)

    pk to sk
  }

  /**
   * Encapsulates a shared secret using the ML-KEM-512 public key (FIPS 203 §7, Algorithm 17).
   *
   * Uses the provided 32 bytes of randomness [coins] as the message m. Derives the shared secret K
   * and encryption coins r via G = SHA3-512(m || H(pk)), encrypts m under the public key with coins
   * r, and returns (ciphertext, sharedSecret).
   *
   * This is the deterministic variant (Encaps_internal): no randomness is sampled internally —
   * [coins] must be cryptographically secure.
   *
   * @param publicKey 800-byte ML-KEM-512 public key
   * @param coins 32 bytes of cryptographically secure randomness
   * @return a pair of (ciphertext, sharedSecret) byte arrays
   */
  public fun encapsDerand(
      publicKey: ByteArray,
      coins: ByteArray,
  ): Result<Pair<ByteArray, ByteArray>> = runCatching {
    require(publicKey.size == MLKEM_PUBLICKEYBYTES) {
      "publicKey must be $MLKEM_PUBLICKEYBYTES bytes, got ${publicKey.size}"
    }
    require(coins.size == MLKEM_SYMBYTES) {
      "coins must be $MLKEM_SYMBYTES bytes, got ${coins.size}"
    }

    val ciphertext = ByteArray(MLKEM_CIPHERTEXTBYTES)
    val sharedSecret = ByteArray(MLKEM_SSBYTES)

    // buf = m || H(pk)  (64 bytes)
    val buf = ByteArray(2 * MLKEM_SYMBYTES)
    coins.copyInto(buf, 0, 0, MLKEM_SYMBYTES)
    SHA3_256PureK.digest(publicKey)
        .copyInto(
            buf,
            MLKEM_SYMBYTES,
            0,
            MLKEM_SYMBYTES,
        )

    // kr = G(buf) = SHA3-512(buf) → (K̄, K) [64 bytes]
    val kr = SHA3_512PureK.digest(buf)

    // CPA encrypt: message = buf[:32], coins = kr[32:64]
    indcpaEncrypt(ciphertext, 0, buf, 0, publicKey, 0, kr, MLKEM_SYMBYTES)

    // Shared secret = K̄ = kr[:32]
    kr.copyInto(sharedSecret, 0, 0, MLKEM_SYMBYTES)

    ciphertext to sharedSecret
  }

  /**
   * Generates a shared secret and ciphertext using the ML-KEM-512 public key (FIPS 203 §7,
   * Algorithm 20). Internal randomness is sampled via the platform CSPRNG.
   *
   * @param publicKey 800-byte ML-KEM-512 public key
   * @return a pair of (ciphertext, sharedSecret) byte arrays
   */
  public fun encaps(publicKey: ByteArray): Result<Pair<ByteArray, ByteArray>> = runCatching {
    val coins = randomBytes(MLKEM_SYMBYTES)
    encapsDerand(publicKey, coins).getOrThrow()
  }

  /**
   * Decapsulates a shared secret from ciphertext using the ML-KEM-512 secret key (FIPS 203 §7,
   * Algorithm 21 / Decaps_internal Algorithm 18).
   *
   * Recovers the message m' from the ciphertext, re-derives (K̄', K') via G(m' || H(pk)),
   * re-encrypts to produce c', and verifies c == c'. If the verification passes, the shared secret
   * is K̄' (first 32 bytes of G). If it fails, the shared secret is the implicit rejection value
   * J(z || c).
   *
   * @param secretKey 1632-byte ML-KEM-512 secret key
   * @param ciphertext 768-byte ciphertext
   * @return the 32-byte shared secret
   */
  public fun decaps(
      secretKey: ByteArray,
      ciphertext: ByteArray,
  ): Result<ByteArray> = runCatching {
    require(secretKey.size == MLKEM_SECRETKEYBYTES) {
      "secretKey must be $MLKEM_SECRETKEYBYTES bytes, got ${secretKey.size}"
    }
    require(ciphertext.size == MLKEM_CIPHERTEXTBYTES) {
      "ciphertext must be $MLKEM_CIPHERTEXTBYTES bytes, got ${ciphertext.size}"
    }

    val pk =
        secretKey.copyOfRange(
            MLKEM_INDCPA_SECRETKEYBYTES,
            MLKEM_INDCPA_SECRETKEYBYTES + MLKEM_PUBLICKEYBYTES,
        )
    val h =
        secretKey.copyOfRange(
            MLKEM_SECRETKEYBYTES - 2 * MLKEM_SYMBYTES,
            MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES,
        )
    val z =
        secretKey.copyOfRange(
            MLKEM_SECRETKEYBYTES - MLKEM_SYMBYTES,
            MLKEM_SECRETKEYBYTES,
        )

    // 1. Decrypt to recover message m'
    val mPrime = ByteArray(MLKEM_SYMBYTES)
    indcpaDecrypt(mPrime, 0, ciphertext, 0, secretKey, 0)

    // 2. (K̄', K') ← G(m' || h) where h = H(pk)
    val buf = ByteArray(2 * MLKEM_SYMBYTES)
    mPrime.copyInto(buf, 0, 0, MLKEM_SYMBYTES)
    h.copyInto(buf, MLKEM_SYMBYTES, 0, MLKEM_SYMBYTES)
    val kr = SHA3_512PureK.digest(buf)

    // 3. Implicit rejection key: K = J(z || c)
    var sharedSecret = rkprf(z, 0, ciphertext, 0)

    // 4. Re-encrypt: c' ← K-PKE.Encrypt(pk, m', K')
    val cmp = ByteArray(MLKEM_CIPHERTEXTBYTES)
    indcpaEncrypt(cmp, 0, buf, 0, pk, 0, kr, MLKEM_SYMBYTES)

    // 5. If c == c', use K̄' (first 32 bytes of G) instead of implicit rejection
    val fail = verify(ciphertext, 0, cmp, 0, MLKEM_CIPHERTEXTBYTES)
    cmov(sharedSecret, 0, kr, 0, MLKEM_SYMBYTES, 1 - fail)

    sharedSecret
  }
}

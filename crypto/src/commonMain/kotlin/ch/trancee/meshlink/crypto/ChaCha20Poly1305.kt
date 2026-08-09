/*
 * ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
 *
 * Pure-Kotlin, constant-time authenticated encryption with an internal nonce
 * (ADR-0005). The caller never supplies a nonce — [encrypt] generates a fresh
 * 96-bit nonce per call and returns it prepended to the ciphertext and tag:
 *
 *   output = nonce(12) || ciphertext || tag(16)
 *
 * The MAC key is the first 32 bytes of ChaCha20 keystream block 0 (counter 0);
 * the encryption stream starts at counter 1 (RFC 8439 §2.8).
 *
 * [encryptWithNonce] / [decryptWithNonce] are exposed for testing (KAT vectors
 * and Wycheproof vectors supply explicit nonces and AAD). They return
 * `ciphertext || tag` (without the nonce prefix).
 *
 * Decrypt returns `null` on authentication failure (tag mismatch or too-short input),
 * isolating crypto failures from programming errors. Key/nonce size validation
 * uses `require()` (matching `X25519.compute`/`Ed25519.sign`), while ciphertext
 * integrity failures return `null` (matching `Ed25519.verify`'s no-throw pattern).
 */
package ch.trancee.meshlink.crypto

/** ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) with internal nonce (ADR-0005). */
internal object ChaCha20Poly1305PureK {

  /** Key size in bytes (32 = 256 bits). */
  internal const val KEY_SIZE: Int = 32

  /** Nonce size in bytes (12 = 96 bits). */
  internal const val NONCE_SIZE: Int = 12

  /** Poly1305 tag size in bytes (16 = 128 bits). */
  internal const val TAG_SIZE: Int = 16

  // ------------------------------------------------------------------
  // Public AEAD API (internal nonce per ADR-0005)
  // ------------------------------------------------------------------

  /**
   * Encrypts [message] with ChaCha20-Poly1305, generating a fresh random nonce.
   *
   * Output format: `nonce(12) || ciphertext || tag(16)`.
   *
   * @param key 32-byte key.
   * @param message plaintext to encrypt.
   * @return `nonce || ciphertext || tag` (length = 12 + message.size + 16).
   */
  fun encrypt(@Secret key: ByteArray, message: ByteArray): ByteArray {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    val nonce = randomBytes(NONCE_SIZE)
    val cipherWithTag = encryptWithNonce(key, nonce, ByteArray(0), message)
    return nonce + cipherWithTag
  }

  /**
   * Decrypts and authenticates [ciphertext] (format: `nonce(12) || ciphertext || tag(16)`).
   *
   * @param key 32-byte key.
   * @param ciphertext `nonce || ciphertext || tag` blob produced by [encrypt].
   * @return plaintext on success, or `null` if authentication fails or input is too short.
   */
  fun decrypt(@Secret key: ByteArray, ciphertext: ByteArray): ByteArray? {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    if (ciphertext.size < NONCE_SIZE + TAG_SIZE) return null
    val nonce = ciphertext.copyOfRange(0, NONCE_SIZE)
    val cipherWithTag = ciphertext.copyOfRange(NONCE_SIZE, ciphertext.size)
    return decryptWithNonce(key, nonce, ByteArray(0), cipherWithTag)
  }

  // ------------------------------------------------------------------
  // Nonce-explicit variants (for KAT / Wycheproof testing)
  // ------------------------------------------------------------------

  /**
   * Encrypts [plaintext] with ChaCha20-Poly1305 using an explicit [nonce] and [aad].
   *
   * Output format: `ciphertext || tag(16)` (nonce not included).
   *
   * @param key 32-byte key.
   * @param nonce 12-byte nonce (must be unique for a given key).
   * @param aad additional authenticated data (authenticated but not encrypted).
   * @param plaintext data to encrypt.
   * @return `ciphertext || tag` (length = plaintext.size + 16).
   */
  fun encryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      plaintext: ByteArray,
  ): ByteArray {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }

    // MAC key = first 32 bytes of ChaCha20 block 0 (counter = 0).
    val macKey = ChaCha20.block(key, 0, nonce).copyOf(32)

    // Ciphertext = ChaCha20 encryption from counter 1.
    val ciphertext = ChaCha20.streamXor(key, nonce, 1, plaintext)

    // MAC data: AAD + pad + ciphertext + pad + aadLen(8) + ctLen(8).
    val macData = macDataRfc8439(aad, ciphertext)

    // Tag = Poly1305(macKey, macData).
    val tag = Poly1305.mac(macKey, macData)

    return ciphertext + tag
  }

  /**
   * Decrypts and authenticates [ciphertextWithTag] (format: `ciphertext || tag`) using an explicit
   * [nonce] and [aad].
   *
   * @param key 32-byte key.
   * @param nonce 12-byte nonce.
   * @param aad additional authenticated data.
   * @param ciphertextWithTag `ciphertext || tag` blob.
   * @return plaintext on success, or `null` if authentication fails.
   */
  fun decryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      ciphertextWithTag: ByteArray,
  ): ByteArray? {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }

    if (ciphertextWithTag.size < TAG_SIZE) return null

    val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - TAG_SIZE)
    val tag =
        ciphertextWithTag.copyOfRange(ciphertextWithTag.size - TAG_SIZE, ciphertextWithTag.size)

    // MAC key = first 32 bytes of ChaCha20 block 0 (counter = 0).
    val macKey = ChaCha20.block(key, 0, nonce).copyOf(32)

    // Recompute MAC over the same data.
    val macData = macDataRfc8439(aad, ciphertext)
    val expectedTag = Poly1305.mac(macKey, macData)

    // Constant-time comparison — returns false on mismatch without branching on secret.
    if (!ctEqual(expectedTag, tag)) return null

    // Tag verified — decrypt ciphertext (counter 1).
    return ChaCha20.streamXor(key, nonce, 1, ciphertext)
  }

  // ------------------------------------------------------------------
  // RFC 8439 §2.8 MAC-data construction
  // ------------------------------------------------------------------

  /**
   * Constructs the Poly1305 MAC input per RFC 8439 §2.8:
   * ```
   *   AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || aadLen(8) || ctLen(8)
   * ```
   *
   * Lengths are encoded as 64-bit little-endian integers.
   */
  private fun macDataRfc8439(aad: ByteArray, ciphertext: ByteArray): ByteArray {
    val aadPaddedLen = if (aad.size % 16 == 0) aad.size else aad.size + 16 - (aad.size % 16)
    val ctPaddedLen =
        if (ciphertext.size % 16 == 0) ciphertext.size
        else ciphertext.size + 16 - (ciphertext.size % 16)
    val macData = ByteArray(aadPaddedLen + ctPaddedLen + 16)
    aad.copyInto(macData, 0)
    ciphertext.copyInto(macData, aadPaddedLen)
    ChaCha20.store64LE(macData, aadPaddedLen + ctPaddedLen, aad.size.toLong())
    ChaCha20.store64LE(macData, aadPaddedLen + ctPaddedLen + 8, ciphertext.size.toLong())
    return macData
  }

  // ------------------------------------------------------------------
  // Constant-time helpers
  // ------------------------------------------------------------------

  /**
   * Constant-time byte-array comparison.
   *
   * Always scans `min(a.size, b.size)` bytes (the MAC and tag are both 16 bytes, so the length is
   * non-secret). The result is zero only when all bytes match and both lengths are equal. Length is
   * folded into the accumulation via XOR so no early-exit branch leaks size information.
   */
  private fun ctEqual(a: ByteArray, b: ByteArray): Boolean {
    var acc = a.size xor b.size
    val len = minOf(a.size, b.size)
    for (i in 0 until len) {
      acc = acc or (a[i].toInt() xor b[i].toInt())
    }
    return acc == 0
  }
}

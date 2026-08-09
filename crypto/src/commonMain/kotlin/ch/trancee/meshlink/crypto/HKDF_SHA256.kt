package ch.trancee.meshlink.crypto

import kotlin.math.min

/**
 * HKDF-SHA256 (RFC 5869). Pure-Kotlin, constant-time, built on ticket 05's HMAC-SHA256.
 *
 * The construction is:
 * - Extract: PRK = HMAC-Hash(salt, IKM)
 * - Expand: T(1) = HMAC-Hash(PRK, T(0) | info | 0x01), T(2) = HMAC-Hash(PRK, T(1) | info | 0x02),
 *   OKM = first L octets of T(1) | T(2) | ... | T(N) where N = ceil(L / HashLen).
 *
 * where HashLen = 32 (SHA-256 output). If salt is not provided, it defaults to a string of HashLen
 * zero octets (RFC 5869 §2.2). L must not exceed 255 * HashLen (RFC 5869 §2.3).
 *
 * Constant-time discipline (ADR-0003):
 * - [ikm] and [prk] are annotated [Secret]; [salt] and [info] are public per RFC 5869 §2.1/§2.2.
 * - The salt-length check branches on [salt.isEmpty] — a public property, not a secret parameter
 *   name, so the detekt [ConstantTimeRule] does not flag it.
 * - The expand loop count is derived from [outputLength] (public), not from secret material.
 * - [HMAC_SHA256] compression is fixed-round per ticket 05.
 */
internal object HKDF_SHA256PureK {

  /** SHA-256 output length in bytes (RFC 6234 §5.1). */
  private const val HASH_LENGTH = 32

  /** Maximum HKDF output length: 255 * HashLen (RFC 5869 §2.3). */
  private const val MAX_OUTPUT_LENGTH = 255 * HASH_LENGTH

  /**
   * Computes HKDF-SHA256 over [ikm] using [salt] and [info], producing [outputLength] bytes.
   *
   * @param ikm the secret input keying material.
   * @param salt the non-secret salt value (empty for HashLen-zeros default per RFC 5869 §2.2).
   * @param info the non-secret context and application-specific information.
   * @param outputLength the number of output bytes (must be in 0..255*HashLen).
   * @return [outputLength] bytes of derived keying material.
   */
  fun digest(
      @Secret ikm: ByteArray,
      salt: ByteArray,
      info: ByteArray,
      outputLength: Int,
  ): ByteArray {
    val extractedKey = extract(ikm, salt)
    return expand(extractedKey, info, outputLength)
  }

  /**
   * HKDF-Extract(salt, IKM) -> PRK (RFC 5869 §2.2).
   *
   * @param ikm the secret input keying material.
   * @param salt the non-secret salt (empty defaults to HashLen zeros).
   * @return 32-byte PRK.
   */
  fun extract(@Secret ikm: ByteArray, salt: ByteArray): ByteArray {
    val saltBytes = if (salt.isEmpty()) ByteArray(HASH_LENGTH) else salt
    return HMAC_SHA256PureK.digest(saltBytes, ikm)
  }

  /**
   * HKDF-Expand(PRK, info, L) -> OKM (RFC 5869 §2.3).
   *
   * @param prk the pseudorandom key (output of [extract]).
   * @param info the non-secret context and application-specific information.
   * @param outputLength the number of output bytes (must be in 0..255*HashLen).
   * @return [outputLength] bytes of derived keying material.
   */
  fun expand(@Secret prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
    if (outputLength < 0) {
      throw IllegalArgumentException("output length must be non-negative")
    }
    if (outputLength > MAX_OUTPUT_LENGTH) {
      throw IllegalArgumentException("output length exceeds 255*HashLen = $MAX_OUTPUT_LENGTH")
    }
    val blockCount = (outputLength + HASH_LENGTH - 1) / HASH_LENGTH
    val output = ByteArray(outputLength)
    var previousBlock = ByteArray(0)
    for (blockNumber in 1..blockCount) {
      val message = previousBlock + info + byteArrayOf(blockNumber.toByte())
      previousBlock = HMAC_SHA256PureK.digest(prk, message)
      val startOffset = (blockNumber - 1) * HASH_LENGTH
      val copyLength = min(HASH_LENGTH, outputLength - startOffset)
      previousBlock.copyInto(output, startOffset, 0, copyLength)
    }
    return output
  }
}

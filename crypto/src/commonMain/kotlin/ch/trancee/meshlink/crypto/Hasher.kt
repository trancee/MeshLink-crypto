/*
 * Public API hash facade (ADR-0005, ADR-0002).
 *
 * Stateless, thread-safe entry points for message digests. Each primitive
 * routes through the per-primitive native-or-pure-K dispatch (expect/actual)
 * transparently — callers need not know which provider is active.
 *
 * All methods return [Result] to avoid exceptions crossing the KMP boundary.
 */
package ch.trancee.meshlink.crypto

/**
 * Message-digest entry points (SHA-256, SHA-512).
 *
 * Example:
 * ```
 * val digest = Hasher.sha256(message).getOrThrow()
 * ```
 */
public object Hasher {
  /**
   * Computes SHA-256 (RFC 6234 §5.1).
   *
   * @return a [Result] containing the 32-byte digest, or [Result.failure] if the native or pure-K
   *   backend raises an error.
   */
  public fun sha256(message: ByteArray): Result<ByteArray> = runCatching { SHA256.digest(message) }

  /**
   * Computes SHA-512 (RFC 6234 §5.2).
   *
   * @return a [Result] containing the 64-byte digest, or [Result.failure] if the native or pure-K
   *   backend raises an error.
   */
  public fun sha512(message: ByteArray): Result<ByteArray> = runCatching { SHA512.digest(message) }

  /**
   * Computes SHA3-256 (FIPS 202 §6.1).
   *
   * @return a [Result] containing the 32-byte digest, or [Result.failure] if the native or pure-K
   *   backend raises an error.
   */
  public fun sha3_256(message: ByteArray): Result<ByteArray> = runCatching {
    SHA3_256.digest(message)
  }

  /**
   * Computes SHA3-512 (FIPS 202 §6.2).
   *
   * @return a [Result] containing the 64-byte digest, or [Result.failure] if the native or pure-K
   *   backend raises an error.
   */
  public fun sha3_512(message: ByteArray): Result<ByteArray> = runCatching {
    SHA3_512.digest(message)
  }

  /**
   * Computes SHAKE256 (FIPS 202 §8.4), an extendable-output function.
   *
   * @param message the bytes to hash.
   * @param outputLength the number of output bytes to squeeze (any positive value).
   * @return a [Result] containing [outputLength] pseudo-random bytes, or [Result.failure] if the
   *   pure-K backend raises an error.
   */
  public fun shake256(message: ByteArray, outputLength: Int): Result<ByteArray> = runCatching {
    SHAKE256.digest(message, outputLength)
  }

  /**
   * Computes SHAKE128 (FIPS 202 §8.3), an extendable-output function.
   *
   * @param message the bytes to hash.
   * @param outputLength the number of output bytes to squeeze (any positive value).
   * @return a [Result] containing [outputLength] pseudo-random bytes, or [Result.failure] if the
   *   pure-K backend raises an error.
   */
  public fun shake128(message: ByteArray, outputLength: Int): Result<ByteArray> = runCatching {
    SHAKE128.digest(message, outputLength)
  }
}

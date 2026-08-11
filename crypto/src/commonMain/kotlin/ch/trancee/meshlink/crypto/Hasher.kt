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
}

/*
 * Platform-agnostic CSPRNG entry point (ADR-0005).
 *
 * ChaCha20-Poly1305 generates a fresh 96-bit nonce per call to [ChaCha20Poly1305.encrypt]
 * so the caller never supplies a nonce (internal nonce). The [randomBytes] function
 * delegates to each platform's native CSPRNG:
 *
 * - JVM / Android: [java.security.SecureRandom]
 * - iOS arm64:     Security framework [SecRandomCopyBytes]
 *
 * This is infrastructure, not a crypto primitive — platform crypto is acceptable here
 * because nonce generation does not run on a secret-dependent code path (ADR-0003).
 */
/*
* Platform-agnostic CSPRNG entry point (ADR-0005).

* ChaCha20-Poly1305 generates a fresh 96-bit nonce per call to [ChaCha20Poly1305.encrypt]
* so the caller never supplies a nonce (internal nonce). The [randomBytes] function
* delegates to each platform's native CSPRNG:
*
* - JVM / Android: [java.security.SecureRandom]
* - iOS arm64:     Security framework [SecRandomCopyBytes]
*
* This is infrastructure, not a crypto primitive — platform crypto is acceptable here
* because nonce generation does not run on a secret-dependent code path (ADR-0003).
*/
package ch.trancee.meshlink.crypto

/**
 * Fills a byte array of [size] bytes with cryptographically secure random bytes.
 *
 * Can be used by consumers to generate random private keys (e.g. 32 bytes for Ed25519 or X25519
 * seeds, 32 bytes for ChaCha20-Poly1305 symmetric keys).
 *
 * Example:
 * ```
 * val privateKey = PrivateKey(randomBytes(32))
 * val nonce = randomBytes(12)
 * ```
 */
public expect fun randomBytes(size: Int): ByteArray

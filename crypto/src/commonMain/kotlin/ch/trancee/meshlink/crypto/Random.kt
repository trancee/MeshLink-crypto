/*
 * Platform-agnostic CSPRNG entry point for internal nonce generation (ADR-0005).
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
package ch.trancee.meshlink.crypto

/**
 * Fills a byte array of [size] bytes with cryptographically secure random bytes.
 *
 * Used only for internal AEAD nonce generation (ADR-0005).
 */
internal expect fun randomBytes(size: Int): ByteArray

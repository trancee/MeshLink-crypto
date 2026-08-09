/*
 * JVM CSPRNG actual for internal nonce generation (ADR-0005).
 */
package ch.trancee.meshlink.crypto

import java.security.SecureRandom

private val secureRandom = SecureRandom()

internal actual fun randomBytes(size: Int): ByteArray {
  val bytes = ByteArray(size)
  secureRandom.nextBytes(bytes)
  return bytes
}

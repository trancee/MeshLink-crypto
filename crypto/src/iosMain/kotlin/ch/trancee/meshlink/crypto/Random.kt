/*
 * iOS CSPRNG actual for internal nonce generation (ADR-0005).
 *
 * Uses Security framework [SecRandomCopyBytes] (kSecRandomDefault), the same
 * source backing Kotlin/Native's own kotlin.random.
 */
package ch.trancee.meshlink.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

@OptIn(ExperimentalForeignApi::class)
internal actual fun randomBytes(size: Int): ByteArray {
  val bytes = ByteArray(size)
  bytes.usePinned { pinned ->
    val result =
        SecRandomCopyBytes(
            rnd = kSecRandomDefault,
            count = size.toULong(),
            bytes = pinned.addressOf(0),
        )
    require(result == 0) { "SecRandomCopyBytes failed with code $result" }
  }
  return bytes
}

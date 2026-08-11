/*
 * iOS actual for SHA-256 (ADR-0002).
 *
 * Thin dispatch wrapper: native CommonCrypto → PureK fallback. The native
 * dispatch logic lives in CryptoBridge.kt, keeping this file free of
 * branching over @Secret data for the detekt ConstantTimeRule (ADR-0003).
 */

package ch.trancee.meshlink.crypto

internal actual object SHA256 {
  actual fun digest(@Secret message: ByteArray): ByteArray =
      sha256Native(message) ?: SHA256PureK.digest(message)
}

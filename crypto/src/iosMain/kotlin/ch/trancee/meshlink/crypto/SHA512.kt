/*
 * iOS actual for SHA-512 (ADR-0002).
 *
 * Thin dispatch wrapper: native CommonCrypto → PureK fallback. The native
 * dispatch logic lives in CryptoBridge.kt, keeping this file free of
 * branching over @Secret data for the detekt ConstantTimeRule (ADR-0003).
 */
package ch.trancee.meshlink.crypto

internal actual object SHA512 {
  actual fun digest(@Secret message: ByteArray): ByteArray =
      sha512Native(message) ?: SHA512PureK.digest(message)
}

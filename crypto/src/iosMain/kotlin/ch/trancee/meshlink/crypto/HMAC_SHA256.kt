/*
 * iOS actual for HMAC-SHA256 (ADR-0002).
 *
 * Thin dispatch wrapper: native CommonCrypto → PureK fallback. The native
 * dispatch logic lives in CryptoBridge.kt, keeping this file free of
 * branching over @Secret data for the detekt ConstantTimeRule (ADR-0003).
 */
package ch.trancee.meshlink.crypto

internal actual object HMAC_SHA256 {
  actual fun digest(@Secret key: ByteArray, @Secret message: ByteArray): ByteArray =
      hmacSha256Native(key, message) ?: HMAC_SHA256PureK.digest(key, message)

  actual fun verify(
      @Secret key: ByteArray,
      @Secret message: ByteArray,
      @Secret tag: ByteArray,
  ): Boolean =
      hmacSha256VerifyNative(key, message, tag) ?: HMAC_SHA256PureK.verify(key, message, tag)
}

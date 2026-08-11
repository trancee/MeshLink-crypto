/*
 * JVM actual for HMAC-SHA256 (ADR-0002).
 *
 * Delegates to the JCA bridge with a PureK fallback. The JCA dispatch logic
 * lives in CryptoBridge.kt (no @Secret params), keeping the detekt
 * ConstantTimeRule (ADR-0003) from flagging provider-selection branches.
 * Key normalization (RFC 2104 §3, keys longer than B=64 are first SHA-256-hashed)
 * is handled by JCA's Mac implementation.
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

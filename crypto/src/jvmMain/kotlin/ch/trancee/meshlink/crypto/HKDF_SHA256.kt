/*
 * JVM actual for HKDF-SHA256 (ADR-0002).
 *
 * Delegates to the CryptoBridge with a PureK fallback. The HKDF
 * implementation uses platform JCA HMAC-SHA256; if unavailable, falls
 * back to HKDF_SHA256PureK.
 */
package ch.trancee.meshlink.crypto

internal actual object HKDF_SHA256 {
  actual fun digest(
      @Secret ikm: ByteArray,
      salt: ByteArray,
      info: ByteArray,
      outputLength: Int,
  ): ByteArray =
      hkdfSha256Native(ikm, salt, info, outputLength)
          ?: HKDF_SHA256PureK.digest(ikm, salt, info, outputLength)

  actual fun extract(@Secret ikm: ByteArray, salt: ByteArray): ByteArray =
      hkdfSha256ExtractNative(ikm, salt) ?: HKDF_SHA256PureK.extract(ikm, salt)

  actual fun expand(@Secret prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray =
      hkdfSha256ExpandNative(prk, info, outputLength)
          ?: HKDF_SHA256PureK.expand(prk, info, outputLength)
}

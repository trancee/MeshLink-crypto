package ch.trancee.meshlink.crypto

internal actual object HKDF_SHA256 {
  actual fun digest(
      @Secret ikm: ByteArray,
      salt: ByteArray,
      info: ByteArray,
      outputLength: Int,
  ): ByteArray = HKDF_SHA256PureK.digest(ikm, salt, info, outputLength)

  actual fun extract(@Secret ikm: ByteArray, salt: ByteArray): ByteArray =
      HKDF_SHA256PureK.extract(ikm, salt)

  actual fun expand(@Secret prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray =
      HKDF_SHA256PureK.expand(prk, info, outputLength)
}

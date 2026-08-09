package ch.trancee.meshlink.crypto

internal actual object HMAC_SHA256 {
  actual fun digest(@Secret key: ByteArray, @Secret message: ByteArray): ByteArray =
      HMAC_SHA256PureK.digest(key, message)

  actual fun verify(
      @Secret key: ByteArray,
      @Secret message: ByteArray,
      @Secret tag: ByteArray,
  ): Boolean = HMAC_SHA256PureK.verify(key, message, tag)
}

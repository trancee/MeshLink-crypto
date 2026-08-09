package ch.trancee.meshlink.crypto

public actual object SHA256 {
  actual fun digest(@Secret message: ByteArray): ByteArray = SHA256PureK.digest(message)
}

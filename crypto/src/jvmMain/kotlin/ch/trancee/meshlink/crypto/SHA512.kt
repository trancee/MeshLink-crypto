package ch.trancee.meshlink.crypto

internal actual object SHA512 {
  actual fun digest(@Secret message: ByteArray): ByteArray = SHA512PureK.digest(message)
}

package ch.trancee.meshlink.crypto

internal actual object Ed25519 {
  actual fun publicKeyFromPrivate(secretKey: ByteArray): ByteArray =
      Ed25519PureK.publicKeyFromPrivate(secretKey)

  actual fun sign(@Secret secretKey: ByteArray, message: ByteArray): ByteArray =
      Ed25519PureK.sign(secretKey, message)

  actual fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
      Ed25519PureK.verify(publicKey, message, signature)
}

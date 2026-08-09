package ch.trancee.meshlink.crypto

internal actual object ChaCha20Poly1305 {
  actual fun encrypt(@Secret key: ByteArray, message: ByteArray): ByteArray =
      ChaCha20Poly1305PureK.encrypt(key, message)

  actual fun decrypt(@Secret key: ByteArray, ciphertext: ByteArray): ByteArray? =
      ChaCha20Poly1305PureK.decrypt(key, ciphertext)

  actual fun encryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      plaintext: ByteArray,
  ): ByteArray = ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad, plaintext)

  actual fun decryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      ciphertextWithTag: ByteArray,
  ): ByteArray? = ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, aad, ciphertextWithTag)
}

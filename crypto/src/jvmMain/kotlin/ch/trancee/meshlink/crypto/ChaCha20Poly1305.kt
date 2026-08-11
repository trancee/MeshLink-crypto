/*
 * JVM actual for ChaCha20-Poly1305 (ADR-0005, ADR-0002, ADR-0008).
 *
 * Thin dispatch wrapper: tries the injected CryptoProvider, then JCA
 * Cipher ("ChaCha20-Poly1305"), falling back to ChaCha20Poly1305PureK on
 * any failure. The actual JCA logic lives in CryptoBridge.kt (no @Secret
 * params, satisfying the detekt ConstantTimeRule — ADR-0003).
 *
 * Uses javax.crypto.Cipher ("ChaCha20-Poly1305") with IvParameterSpec.
 * The JCA cipher produces ciphertext || tag (16-byte Poly1305 tag), matching
 * ChaCha20Poly1305PureK.encryptWithNonce exactly. The public encrypt/decrypt
 * entrypoints prepend/strip an internal 12-byte nonce per ADR-0005.
 *
 */
package ch.trancee.meshlink.crypto

internal actual object ChaCha20Poly1305 {
  actual fun encrypt(@Secret key: ByteArray, message: ByteArray): ByteArray =
      chacha20Poly1305EncryptNative(key, message) ?: ChaCha20Poly1305PureK.encrypt(key, message)

  actual fun decrypt(@Secret key: ByteArray, ciphertext: ByteArray): ByteArray? =
      chacha20Poly1305DecryptNative(key, ciphertext)
          ?: ChaCha20Poly1305PureK.decrypt(key, ciphertext)

  actual fun encryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      plaintext: ByteArray,
  ): ByteArray =
      chacha20Poly1305EncryptWithNonceNative(key, nonce, aad, plaintext)
          ?: ChaCha20Poly1305PureK.encryptWithNonce(key, nonce, aad, plaintext)

  actual fun decryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      ciphertextWithTag: ByteArray,
  ): ByteArray? =
      chacha20Poly1305DecryptWithNonceNative(key, nonce, aad, ciphertextWithTag)
          ?: ChaCha20Poly1305PureK.decryptWithNonce(key, nonce, aad, ciphertextWithTag)
}

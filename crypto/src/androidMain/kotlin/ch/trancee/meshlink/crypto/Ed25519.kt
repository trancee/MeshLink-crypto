/*
 * Android actual for Ed25519 signatures (ADR-0002, ADR-0008).
 *
 * Thin dispatch wrapper: provider → JCA → PureK fallback. The JCA logic
 * lives in androidMain/CryptoBridge.kt, keeping this file free of
 * @Secret branches for the detekt ConstantTimeRule (ADR-0003).
 *
 * Uses PKCS#8 / X.509 encodings for Ed25519 key material (OID 1.3.101.112).
 */
package ch.trancee.meshlink.crypto

internal actual object Ed25519 {
  actual fun publicKeyFromPrivate(secretKey: ByteArray): ByteArray =
      ed25519PublicKeyFromPrivateNative(secretKey) ?: Ed25519PureK.publicKeyFromPrivate(secretKey)

  actual fun sign(@Secret secretKey: ByteArray, message: ByteArray): ByteArray =
      ed25519SignNative(secretKey, message) ?: Ed25519PureK.sign(secretKey, message)

  actual fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
      ed25519VerifyNative(publicKey, message, signature)
          ?: Ed25519PureK.verify(publicKey, message, signature)
}

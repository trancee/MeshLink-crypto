/*
 * iOS actual for Ed25519 signatures (ADR-0002, ADR-0008).
 *
 * Thin dispatch wrapper: provider → Security.framework → PureK fallback. The
 * native dispatch logic lives in CryptoBridge.kt, keeping this file free
 * of branching over @Secret data for the detekt ConstantTimeRule (ADR-0003).
 */
package ch.trancee.meshlink.crypto

internal actual object Ed25519 {
  actual fun publicKeyFromPrivate(secretKey: ByteArray): ByteArray =
      ed25519PublicKeyFromPrivateNative(secretKey) ?: Ed25519PureK.publicKeyFromPrivate(secretKey)

  actual fun sign(@Secret secretKey: ByteArray, message: ByteArray): ByteArray =
      ed25519SignNative(secretKey, message) ?: Ed25519PureK.sign(secretKey, message)

  actual fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
      if (Ed25519PureK.isIdentityPoint(publicKey) || Ed25519PureK.isZeroS(signature)) false
      else ed25519VerifyNative(publicKey, message, signature)
          ?: Ed25519PureK.verify(publicKey, message, signature)
}

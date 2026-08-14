/*
 * JVM actual for Ed25519 signatures (ADR-0002, ADR-0008).
 *
 * Thin dispatch wrapper: tries the injected CryptoProvider, then JCA
 * KeyFactory/Signature ("Ed25519"), falling back to Ed25519PureK on any
 * failure. The actual JCA logic lives in CryptoBridge.kt (no @Secret
 * params, satisfying the detekt ConstantTimeRule — ADR-0003).
 *
 * Ed25519PrivateKeySpec / Ed25519PublicKeySpec were added in Java 15 (available
 * on the JDK 21 toolchain). On Android, raw key material is injected via PKCS#8 /
 * X.509 encodings built from the 32-byte keys with the Ed25519 OID (1.3.101.112).
 *
 */
package ch.trancee.meshlink.crypto

internal actual object Ed25519 {
  actual fun publicKeyFromPrivate(secretKey: ByteArray): ByteArray =
      ed25519PublicKeyFromPrivateNative(secretKey) ?: Ed25519PureK.publicKeyFromPrivate(secretKey)

  actual fun sign(@Secret secretKey: ByteArray, message: ByteArray): ByteArray =
      ed25519SignNative(secretKey, message) ?: Ed25519PureK.sign(secretKey, message)

  actual fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
      if (Ed25519PureK.isIdentityPoint(publicKey) || Ed25519PureK.isZeroS(signature)) false
      else
          ed25519VerifyNative(publicKey, message, signature)
              ?: Ed25519PureK.verify(publicKey, message, signature)
}

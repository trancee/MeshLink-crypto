/*
 * JVM actual for X25519 key agreement (ADR-0002, ADR-0008).
 *
 * Thin dispatch wrapper: tries the injected CryptoProvider, then JCA
 * KeyAgreement ("X25519"), falling back to X25519PureK on any failure.
 * The actual JCA logic lives in CryptoBridge.kt (no @Secret params,
 * satisfying the detekt ConstantTimeRule — ADR-0003).
 *
 */
package ch.trancee.meshlink.crypto

internal actual object X25519 {
  actual fun compute(@Secret scalar: ByteArray, @Secret u: ByteArray): ByteArray {
    val result = x25519Native(scalar, u) ?: X25519PureK.compute(scalar, u)
    if (X25519PureK.isAllZeroSharedSecret(result)) {
      throw IllegalArgumentException("X25519 shared secret is all-zero — rejecting low-order point (RFC 7748 §6.1)")
    }
    return result
  }
}

/*
 * JVM actual for SHA-512 (ADR-0002).
 *
 * Delegates to the JCA bridge with a PureK fallback. The JCA dispatch logic
 * lives in CryptoBridge.kt (no @Secret params), keeping the detekt
 * ConstantTimeRule (ADR-0003) from flagging provider-selection branches.
 */
package ch.trancee.meshlink.crypto

internal actual object SHA512 {
  actual fun digest(@Secret message: ByteArray): ByteArray =
      sha512Native(message) ?: SHA512PureK.digest(message)
}

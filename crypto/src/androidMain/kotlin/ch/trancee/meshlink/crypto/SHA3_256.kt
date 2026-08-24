/*
 * Android actual for SHA3-256 (ADR-0002).
 *
 * Thin dispatch wrapper: native JCA → PureK fallback. The JCA dispatch logic
 * lives in CryptoBridge.kt (no @Secret params), keeping the detekt
 * ConstantTimeRule (ADR-0003) from flagging provider-selection branches.
 */
package ch.trancee.meshlink.crypto

internal actual object SHA3_256 {
  actual fun digest(@Secret message: ByteArray): ByteArray =
      sha3_256Native(message) ?: SHA3_256PureK.digest(message)
}

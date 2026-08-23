/*
 * iOS actual for SHAKE128 (ADR-0002).
 *
 * Delegates to the bridge with a PureK fallback. The native dispatch logic
 * lives in CryptoBridge.kt (no @Secret params), keeping the detekt
 * ConstantTimeRule (ADR-0003) from flagging provider-selection branches.
 *
 * iOS provides no CommonCrypto or Security.framework C-API for SHAKE128 —
 * shake128Native returns null, so the pure-Kotlin path is always taken
 * (ADR-0001, ticket 34).
 */
package ch.trancee.meshlink.crypto

internal actual object SHAKE128 {
  actual fun digest(@Secret message: ByteArray, outputLength: Int): ByteArray =
      shake128Native(message, outputLength) ?: SHAKE128PureK.digest(message, outputLength)
}

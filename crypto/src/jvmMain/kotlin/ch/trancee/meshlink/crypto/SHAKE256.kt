/*
 * JVM actual for SHAKE256 (ADR-0002).
 *
 * Delegates to the bridge with a PureK fallback. The native dispatch logic
 * lives in CryptoBridge.kt (no @Secret params), keeping the detekt
 * ConstantTimeRule (ADR-0003) from flagging provider-selection branches.
 *
 * On JDK 21, JCA does not provide a usable SHAKE256 provider in this library's
 * configuration — shake256Native returns null, so the pure-Kotlin path is always
 * taken (ADR-0001, ticket 34).
 */
package ch.trancee.meshlink.crypto

internal actual object SHAKE256 {
  actual fun digest(@Secret message: ByteArray, outputLength: Int): ByteArray =
      shake256Native(message, outputLength) ?: SHAKE256PureK.digest(message, outputLength)
}

/*
 * iOS actual for X25519 key agreement (ADR-0002, ADR-0008).
 *
 * Thin dispatch wrapper: provider → Security.framework → PureK fallback. The
 * native dispatch logic lives in CryptoBridge.kt, keeping this file free
 * of branching over @Secret data for the detekt ConstantTimeRule (ADR-0003).
 */
package ch.trancee.meshlink.crypto

internal actual object X25519 {
  actual fun compute(@Secret scalar: ByteArray, @Secret u: ByteArray): ByteArray =
      x25519Native(scalar, u) ?: X25519PureK.compute(scalar, u)
}

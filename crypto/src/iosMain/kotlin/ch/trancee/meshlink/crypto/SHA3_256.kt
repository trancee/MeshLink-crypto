/*
 * iOS actual for SHA3-256 (FIPS 202 §6.1).
 *
 * iOS provides no CommonCrypto or Security.framework C-API for SHA3-256 accessible via
 * cinterop (CryptoKit is Swift-only, corecrypto SHA3 is private). The pure-Kotlin path is
 * always taken (ADR-0001, ticket 34).
 */
package ch.trancee.meshlink.crypto

internal actual object SHA3_256 {
  actual fun digest(@Secret message: ByteArray): ByteArray =
      sha3_256Native(message) ?: SHA3_256PureK.digest(message)
}

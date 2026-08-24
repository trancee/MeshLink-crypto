/*
 * iOS actual for SHA3-512 (FIPS 202 §6.2).
 *
 * iOS provides no CommonCrypto or Security.framework C-API for SHA3-512 accessible via
 * cinterop (CryptoKit is Swift-only, corecrypto SHA3 is private). The pure-Kotlin path is
 * always taken (ADR-0001, ticket 34).
 */
package ch.trancee.meshlink.crypto

internal actual object SHA3_512 {
  actual fun digest(@Secret message: ByteArray): ByteArray =
      sha3_512Native(message) ?: SHA3_512PureK.digest(message)
}

/*
 * expect/actual dispatch declarations (ADR-0002).
 *
 * Each primitive has one expect object here in commonMain. Platform source sets
 * (jvmMain, androidMain, iosMain) provide the actual, which selects a native
 * crypto provider when available and falls back to the *PureK object (compiled
 * from the same commonMain source) otherwise.
 */
package ch.trancee.meshlink.crypto

/**
 * SHA-256 message digest (RFC 6234 §5.1, §6).
 *
 * Dispatch entry point — native provider when available, otherwise [SHA256PureK].
 */
internal expect object SHA256 {
  fun digest(@Secret message: ByteArray): ByteArray
}

/**
 * SHA-512 message digest (RFC 6234 §5.2, §6.3, §6.4).
 *
 * Dispatch entry point — native provider when available, otherwise [SHA512PureK].
 */
internal expect object SHA512 {
  fun digest(@Secret message: ByteArray): ByteArray
}

/**
 * HMAC-SHA256 (RFC 2104).
 *
 * Dispatch entry point — native provider when available, otherwise [HMAC_SHA256PureK].
 */
internal expect object HMAC_SHA256 {
  fun digest(@Secret key: ByteArray, @Secret message: ByteArray): ByteArray

  fun verify(@Secret key: ByteArray, @Secret message: ByteArray, @Secret tag: ByteArray): Boolean
}

/**
 * HKDF-SHA256 (RFC 5869).
 *
 * Dispatch entry point — native HMAC (platform JCA/CCHmac) when available, otherwise
 * [HKDF_SHA256PureK]. No standard HKDF API exists on minSdk 21 / JDK 21 / any Android API level
 * (javax.crypto.KDF is JDK 25+); HKDF is built on the platform HMAC primitive in CryptoBridge.kt.
 */
internal expect object HKDF_SHA256 {
  fun digest(
      @Secret ikm: ByteArray,
      salt: ByteArray,
      info: ByteArray,
      outputLength: Int,
  ): ByteArray

  fun extract(@Secret ikm: ByteArray, salt: ByteArray): ByteArray

  fun expand(@Secret prk: ByteArray, info: ByteArray, outputLength: Int): ByteArray
}

/**
 * X25519 key agreement (RFC 7748 §5).
 *
 * Dispatch entry point — native provider when available, otherwise [X25519PureK].
 */
internal expect object X25519 {
  fun compute(@Secret scalar: ByteArray, @Secret u: ByteArray): ByteArray

  fun derivePublicKey(scalar: ByteArray): ByteArray
}

/**
 * Ed25519 signatures (RFC 8032 §5.1).
 *
 * Dispatch entry point — native provider when available, otherwise [Ed25519PureK].
 */
internal expect object Ed25519 {
  fun publicKeyFromPrivate(secretKey: ByteArray): ByteArray

  fun sign(@Secret secretKey: ByteArray, message: ByteArray): ByteArray

  fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
}

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) with internal nonce (ADR-0005).
 *
 * Dispatch entry point — native provider when available, otherwise [ChaCha20Poly1305PureK].
 */
internal expect object ChaCha20Poly1305 {
  fun encrypt(@Secret key: ByteArray, message: ByteArray): ByteArray

  fun decrypt(@Secret key: ByteArray, ciphertext: ByteArray): ByteArray?

  fun encryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      plaintext: ByteArray,
  ): ByteArray

  fun decryptWithNonce(
      @Secret key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      ciphertextWithTag: ByteArray,
  ): ByteArray?
}

/**
 * SHAKE256 extendable-output function (FIPS 202 §8.4).
 *
 * Dispatch entry point — native provider when available, otherwise [SHAKE256PureK]. On JDK 21,
 * Android API 21+, and iOS there is no native SHAKE256 C-API or JCA provider that the library can
 * use; the bridge functions return `null` and the pure-Kotlin path is always taken (ADR-0001,
 * ticket 34).
 */
internal expect object SHAKE256 {
  fun digest(@Secret message: ByteArray, outputLength: Int): ByteArray
}

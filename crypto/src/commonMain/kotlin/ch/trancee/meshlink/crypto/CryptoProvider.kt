/*
 * Optional platform-native crypto provider interface (CryptoKit, JCA, or Security.framework).
 *
 * Consuming apps can inject a platform-native implementation at runtime via
 * [setCryptoProvider]. The library routes supported primitives through the
 * provider before falling back to the native C-API (iOS: CommonCrypto /
 * Security.framework; JVM/Android: JCA) or the pure-Kotlin path.
 *
 * On all platforms, [setCryptoProvider] stores the provider and the bridge
 * checks it before falling back.
 *
 * Security note: implementations should keep private keys in the OS key store
 * and never export raw key material. The interface receives raw bytes only
 * because the library operates on raw key bytes (ADR-0005); the provider
 * implementation decides how to import them into the OS key store.
 */
package ch.trancee.meshlink.crypto

/**
 * Optional platform-native crypto provider backed by CryptoKit, JCA, or Security.framework.
 *
 * Each method returns `null` (or `false` for verify) when the provider cannot handle the operation
 * — the library then falls back to its next path (C-API, JCA, or pure-Kotlin). Implementations that
 * do not support a given primitive should return `null` from the `supports*` method rather than
 * throwing.
 */
public interface CryptoProvider {

  // -- X25519 (RFC 7748 §5) -------------------------------------------------

  /** Whether the provider can handle X25519 key agreement. */
  public fun supportsX25519(): Boolean

  /**
   * Computes X25519(scalar, u).
   *
   * @param scalar 32-byte private key (little-endian, per RFC 7748).
   * @param u 32-byte public u-coordinate (little-endian).
   * @return 32-byte shared secret, or `null` if the provider cannot handle it.
   */
  public fun x25519(
      scalar: ByteArray,
      u: ByteArray,
  ): ByteArray?

  // -- Ed25519 (RFC 8032 §5.1) ----------------------------------------------

  /** Whether the provider can handle Ed25519 signing/verification. */
  public fun supportsEd25519(): Boolean

  /**
   * Derives the Ed25519 public key from the 32-byte private seed.
   *
   * @return 32-byte public key, or `null` if the provider cannot handle it.
   */
  public fun ed25519PublicKeyFromPrivate(
      secretKey: ByteArray,
  ): ByteArray?

  /**
   * Signs [message] with the Ed25519 private key derived from [secretKey].
   *
   * @return 64-byte signature, or `null` if the provider cannot handle it.
   */
  public fun ed25519Sign(
      secretKey: ByteArray,
      message: ByteArray,
  ): ByteArray?

  /**
   * Verifies [signature] for [message] against the Ed25519 [publicKey].
   *
   * @return `true` if valid, `false` if invalid, or `null` if the provider cannot handle it.
   */
  public fun ed25519Verify(
      publicKey: ByteArray,
      message: ByteArray,
      signature: ByteArray,
  ): Boolean?

  // -- ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) -------------------------------

  /** Whether the provider can handle ChaCha20-Poly1305 AEAD. */
  public fun supportsChaCha20Poly1305(): Boolean

  /**
   * Encrypts [plaintext] with ChaCha20-Poly1305.
   *
   * Output format: `nonce(12) || ciphertext || tag(16)` (nonce generated internally by the bridge
   * per ADR-0005).
   *
   * @return ciphertext+tag, or `null` if the provider cannot handle it.
   */
  public fun chacha20Poly1305Encrypt(
      key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      plaintext: ByteArray,
  ): ByteArray?

  /**
   * Decrypts and authenticates [ciphertextWithTag] (`ciphertext || tag(16)`).
   *
   * @return plaintext on success, or `null` on authentication failure / when the provider cannot
   *   handle it.
   */
  public fun chacha20Poly1305Decrypt(
      key: ByteArray,
      nonce: ByteArray,
      aad: ByteArray,
      ciphertextWithTag: ByteArray,
  ): ByteArray?
}

/**
 * Sets the platform-native crypto provider (CryptoKit on iOS, JCA/Keystore on JVM/Android).
 *
 * Call this once at app startup from Swift, Java, or Kotlin:
 * ```swift
 * // In the consuming iOS app
 * KMP.setCryptoProvider(CryptoKitProvider())
 * ```
 *
 * Pass `null` to clear the provider. When no provider is set (or a provider returns `null` for a
 * primitive), the library uses its native path (CommonCrypto / Security.framework on iOS, JCA on
 * JVM/Android) or the pure-Kotlin fallback.
 */
public expect fun setCryptoProvider(provider: CryptoProvider?)

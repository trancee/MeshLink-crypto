/*
 * Unified crypto facade (ADR-0005, Candidate #5).
 *
 * Provides a single entry point for all primitives: hashing, HMAC, HKDF,
 * key exchange, signing, and AEAD. Delegates to the per-primitive objects
 * (Hasher, Authenticator, Kdf, KeyExchange, Signer, Aead) without adding
 * logic — existing objects remain available for backward compatibility.
 *
 * All entry points are stateless, thread-safe, and return Result<T> (no
 * exceptions crossing the KMP boundary). Each primitive routes through the
 * per-primitive native-or-pure-K dispatch transparently.
 */
package ch.trancee.meshlink.crypto

/**
 * Unified entry point for all cryptographic primitives.
 *
 * Delegates to the per-primitive facade objects ([Hasher], [Authenticator], [Kdf], [KeyExchange],
 * [Signer], [Aead]). Each method is a zero-overhead delegation — the real dispatch logic lives in
 * the target objects.
 *
 * Example:
 * ```
 * val digest = Crypto.sha256(message)
 * val sharedSecret = Crypto.x25519(PrivateKey(scalar), PublicKey(u))
 * val ciphertext = Crypto.chacha20Poly1305Encrypt(SecretKey(key), message)
 * ```
 *
 * Since this library is pre-1.0, the per-primitive objects ([Hasher.sha256],
 * [Authenticator.hmacSha256], etc.) remain public and are not yet deprecated. Callers may use
 * either style; the unified [Crypto] facade is the preferred forward-looking entry point.
 */
public object Crypto {
  // -- Hashing ----------------------------------------------------------

  /** Computes SHA-256 (RFC 6234 §5.1). Delegates to [Hasher.sha256]. */
  public fun sha256(message: ByteArray): Result<ByteArray> = Hasher.sha256(message)

  /** Computes SHA-512 (RFC 6234 §5.2). Delegates to [Hasher.sha512]. */
  public fun sha512(message: ByteArray): Result<ByteArray> = Hasher.sha512(message)

  // -- HMAC (RFC 2104) -------------------------------------------------

  /** Computes HMAC-SHA256 over [message] using [key]. Delegates to [Authenticator.hmacSha256]. */
  public fun hmacSha256(key: SecretKey, message: ByteArray): Result<ByteArray> =
      Authenticator.hmacSha256(key, message)

  /**
   * Verifies [tag] against HMAC-SHA256 of [message] using [key]. Delegates to
   * [Authenticator.verify].
   */
  public fun verifyHmacSha256(
      key: SecretKey,
      message: ByteArray,
      tag: ByteArray,
  ): Result<Boolean> = Authenticator.verify(key, message, tag)

  // -- HKDF (RFC 5869) -------------------------------------------------

  /** Runs full HKDF-SHA256 (extract + expand). Delegates to [Kdf.hkdfSha256]. */
  public fun hkdfSha256(
      ikm: ByteArray,
      salt: ByteArray,
      info: ByteArray,
      outputLength: Int,
  ): Result<ByteArray> = Kdf.hkdfSha256(ikm, salt, info, outputLength)

  /** HKDF-Extract: PRK = HMAC-SHA256(salt, IKM). Delegates to [Kdf.extract]. */
  public fun extract(ikm: ByteArray, salt: ByteArray): Result<ByteArray> = Kdf.extract(ikm, salt)

  /** HKDF-Expand: OKM = Expand(PRK, info, L). Delegates to [Kdf.expand]. */
  public fun expand(prk: ByteArray, info: ByteArray, outputLength: Int): Result<ByteArray> =
      Kdf.expand(prk, info, outputLength)

  // -- X25519 (RFC 7748 §5) --------------------------------------------

  /** Computes the X25519 shared secret. Delegates to [KeyExchange.x25519]. */
  public fun x25519(scalar: PrivateKey, u: PublicKey): Result<ByteArray> =
      KeyExchange.x25519(scalar, u)

  // -- Ed25519 (RFC 8032 §5.1) -----------------------------------------

  /** Signs [message] with Ed25519 [secretKey]. Delegates to [Signer.ed25519Sign]. */
  public fun ed25519Sign(secretKey: PrivateKey, message: ByteArray): Result<ByteArray> =
      Signer.ed25519Sign(secretKey, message)

  /**
   * Verifies [signature] for [message] against Ed25519 [publicKey]. Delegates to
   * [Signer.ed25519Verify].
   */
  public fun ed25519Verify(
      publicKey: PublicKey,
      message: ByteArray,
      signature: ByteArray,
  ): Result<Boolean> = Signer.ed25519Verify(publicKey, message, signature)

  // -- ChaCha20-Poly1305 (RFC 8439) ------------------------------------

  /**
   * Encrypts [message] with ChaCha20-Poly1305 using [key]. Delegates to
   * [Aead.chacha20Poly1305Encrypt].
   */
  public fun chacha20Poly1305Encrypt(key: SecretKey, message: ByteArray): Result<ByteArray> =
      Aead.chacha20Poly1305Encrypt(key, message)

  /**
   * Decrypts [ciphertext] with ChaCha20-Poly1305 using [key]. Delegates to
   * [Aead.chacha20Poly1305Decrypt].
   */
  public fun chacha20Poly1305Decrypt(
      key: SecretKey,
      ciphertext: ByteArray,
  ): Result<ByteArray?> = Aead.chacha20Poly1305Decrypt(key, ciphertext)
}

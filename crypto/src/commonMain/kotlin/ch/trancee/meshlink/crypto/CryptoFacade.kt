/*
 * Public API facade for MAC, KDF, key exchange, signing, and AEAD (ADR-0005).
 *
 * All entry points are stateless, thread-safe, and return Result<T> (no
 * exceptions crossing the KMP boundary). Each primitive routes through the
 * per-primitive native-or-pure-K dispatch (expect/actual) transparently.
 *
 * Keyed primitives accept typed [SecretKey], [PrivateKey], [PublicKey]
 * handles — never raw ByteArray for key material.
 */
package ch.trancee.meshlink.crypto

/**
 * HMAC-SHA256 (RFC 2104) entry points.
 *
 * Example:
 * ```
 * val tag = Authenticator.hmacSha256(SecretKey(key), message).getOrThrow()
 * ```
 */
public object Authenticator {
  /**
   * Computes HMAC-SHA256 over [message] using [key].
   *
   * @return a [Result] containing the 32-byte tag, or [Result.failure] on error.
   */
  public fun hmacSha256(key: SecretKey, message: ByteArray): Result<ByteArray> = runCatching {
    HMAC_SHA256.digest(key.bytes, message)
  }

  /**
   * Verifies [tag] against HMAC-SHA256 of [message] using [key].
   *
   * Uses a constant-time comparison internally (no early exit).
   *
   * @return [Result.success] with `true` if valid, `false` if the tag does not match.
   */
  public fun verify(key: SecretKey, message: ByteArray, tag: ByteArray): Result<Boolean> =
      runCatching {
        HMAC_SHA256.verify(key.bytes, message, tag)
      }
}

/**
 * HKDF-SHA256 (RFC 5869) entry points.
 *
 * The salt and info parameters are public (non-secret) per RFC 5869 §2.1/§2.2. IKM and PRK are
 * secret; callers who wish to zero them should wrap them in [SecretKey] and call [SecretKey.close]
 * after use.
 */
public object Kdf {
  /**
   * Runs full HKDF-SHA256 (extract + expand).
   *
   * @param ikm the input keying material (secret).
   * @param salt the non-secret salt (empty for HashLen-zeros default per RFC 5869 §2.2).
   * @param info the non-secret context string.
   * @param outputLength the number of output bytes.
   * @return [Result.success] with the OKM, or [Result.failure] on error.
   */
  public fun hkdfSha256(
      ikm: ByteArray,
      salt: ByteArray,
      info: ByteArray,
      outputLength: Int,
  ): Result<ByteArray> = runCatching { HKDF_SHA256.digest(ikm, salt, info, outputLength) }

  /**
   * HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
   *
   * @return [Result.success] with the 32-byte PRK.
   */
  public fun extract(ikm: ByteArray, salt: ByteArray): Result<ByteArray> = runCatching {
    HKDF_SHA256.extract(ikm, salt)
  }

  /**
   * HKDF-Expand: OKM = Expand(PRK, info, L).
   *
   * @return [Result.success] with the derived keying material.
   */
  public fun expand(prk: ByteArray, info: ByteArray, outputLength: Int): Result<ByteArray> =
      runCatching {
        HKDF_SHA256.expand(prk, info, outputLength)
      }
}

/**
 * X25519 key agreement (RFC 7748 §5) entry points.
 *
 * Example:
 * ```
 * val sharedSecret = KeyExchange.x25519(PrivateKey(scalar), PublicKey(u)).getOrThrow()
 * ```
 */
public object KeyExchange {
  /**
   * Computes the X25519 shared secret: scalar * u.
   *
   * @return [Result.success] with the 32-byte shared secret, or [Result.failure] on error.
   */
  public fun x25519(scalar: PrivateKey, u: PublicKey): Result<ByteArray> = runCatching {
    X25519.compute(scalar.bytes, u.bytes)
  }
}

/**
 * Ed25519 signature (RFC 8032 §5.1) entry points.
 *
 * Example:
 * ```
 * val signature = Signer.ed25519Sign(PrivateKey(secretKey), message).getOrThrow()
 * val valid = Signer.ed25519Verify(PublicKey(publicKey), message, signature).getOrThrow()
 * ```
 */
public object Signer {
  /**
   * Signs [message] with the Ed25519 [secretKey].
   *
   * @return [Result.success] with the 64-byte signature, or [Result.failure] on error.
   */
  public fun ed25519Sign(secretKey: PrivateKey, message: ByteArray): Result<ByteArray> =
      runCatching {
        Ed25519.sign(secretKey.bytes, message)
      }

  /**
   * Verifies [signature] for [message] against the Ed25519 [publicKey].
   *
   * @return [Result.success] with `true` if valid, `false` if the signature is invalid.
   */
  public fun ed25519Verify(
      publicKey: PublicKey,
      message: ByteArray,
      signature: ByteArray,
  ): Result<Boolean> = runCatching { Ed25519.verify(publicKey.bytes, message, signature) }
}

/**
 * ChaCha20-Poly1305 AEAD (RFC 8439) entry points.
 *
 * The nonce is internal — [chacha20Poly1305Encrypt] generates a fresh 96-bit nonce per call and
 * returns it prepended to the ciphertext and tag. Callers never supply a nonce (ADR-0005).
 *
 * Output format: `nonce(12) || ciphertext || tag(16)`.
 */
public object Aead {
  /**
   * Encrypts [message] with ChaCha20-Poly1305 using [key].
   *
   * @return [Result.success] with `nonce || ciphertext || tag`, or [Result.failure] on error.
   */
  public fun chacha20Poly1305Encrypt(key: SecretKey, message: ByteArray): Result<ByteArray> =
      runCatching {
        ChaCha20Poly1305.encrypt(key.bytes, message)
      }

  /**
   * Decrypts [ciphertext] (`nonce || ciphertext || tag`) with ChaCha20-Poly1305 using [key].
   *
   * @return [Result.success] with the plaintext on success, [Result.success] with `null` if the
   *   auth tag fails, or [Result.failure] if the input is malformed.
   */
  public fun chacha20Poly1305Decrypt(key: SecretKey, ciphertext: ByteArray): Result<ByteArray?> =
      runCatching {
        ChaCha20Poly1305.decrypt(key.bytes, ciphertext)
      }
}

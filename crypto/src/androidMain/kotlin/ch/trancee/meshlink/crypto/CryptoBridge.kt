/*
 * Android dispatch bridge: CryptoProvider → JCA → PureK fallback.
 *
 * Sibling to jvmMain/CryptoBridge.kt — Android's source set does NOT inherit
 * jvmMain in KMP, so the bridge is duplicated here. The JCA code is identical
 * on both targets.
 *
 * This file contains NO @Secret-annotated parameters, so the detekt ConstantTimeRule
 * (ADR-0003) does not flag the provider-selection or fallback branches.
 *
 * The actual objects (X25519, Ed25519, ChaCha20Poly1305, SHA256, SHA512,
 * HMAC_SHA256) stay thin: they delegate to this bridge via `elvis` and
 * fall back to *PureK on null.
 */
package ch.trancee.meshlink.crypto

import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.SignatureException
import java.security.spec.InvalidKeySpecException
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// PKCS#8 v1 prefix for Ed25519 (16 bytes):
// 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20
private val PKCS8_PREFIX =
    byteArrayOf(
        0x30,
        0x2e,
        0x02,
        0x01,
        0x00,
        0x30,
        0x05,
        0x06,
        0x03,
        0x2b,
        0x65,
        0x70,
        0x04,
        0x22,
        0x04,
        0x20,
    )

// X.509 prefix for Ed25519 public key (12 bytes):
// 30 2a 30 05 06 03 2b 65 70 03 21 00
private val X509_PREFIX =
    byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)

private const val PKCS8_PREFIX_LEN = 16
private const val X509_PREFIX_LEN = 12
private const val KEY_LEN = 32

// ---------------------------------------------------------------------------
// Native availability cache — avoids repeated NoSuchAlgorithmException
// throws on platforms where the JCA algorithm is unavailable (e.g. Android
// API < 29 for X25519/Ed25519/ChaCha20-Poly1305). Set once on the first
// failure; the cryptoProvider check above always takes priority regardless.
// ---------------------------------------------------------------------------
@Volatile private var x25519Fallback: Boolean = false

@Volatile private var ed25519Fallback: Boolean = false

@Volatile private var chacha20Poly1305Fallback: Boolean = false

@Volatile private var sha256Fallback: Boolean = false

@Volatile private var sha512Fallback: Boolean = false

@Volatile private var hmacSha256Fallback: Boolean = false

// ---------------------------------------------------------------------------
// Public entry points (called by the thin JVM/Android actuals)
// ---------------------------------------------------------------------------

internal fun x25519Native(scalar: ByteArray, u: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsX25519() == true) {
    return provider.x25519(scalar, u)
  }
  if (x25519Fallback) return null
  return try {
    val keyFactory = KeyFactory.getInstance("X25519")
    val privateKey =
        keyFactory.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, scalar))
    val publicKey =
        keyFactory.generatePublic(
            XECPublicKeySpec(NamedParameterSpec.X25519, BigInteger(1, u.reversedArray()))
        )
    val keyAgreement = KeyAgreement.getInstance("X25519")
    keyAgreement.init(privateKey)
    keyAgreement.doPhase(publicKey, true)
    keyAgreement.generateSecret()
  } catch (e: NoSuchAlgorithmException) {
    x25519Fallback = true
    null
  } catch (e: InvalidKeyException) {
    null
  } catch (e: InvalidKeySpecException) {
    null
  } catch (e: IllegalStateException) {
    null
  }
}

internal fun x25519DerivePublicKeyNative(scalar: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsX25519() == true) {
    return provider.x25519PublicKeyFromPrivate(scalar)
  }
  if (x25519Fallback) return null
  return try {
    val keyFactory = KeyFactory.getInstance("X25519")
    val privateKey =
        keyFactory.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, scalar))
    val x509Spec =
        keyFactory.getKeySpec(
            privateKey,
            X509EncodedKeySpec::class.java,
        )
    x509Spec.encoded.copyOfRange(X509_PREFIX_LEN, X509_PREFIX_LEN + KEY_LEN)
  } catch (e: NoSuchAlgorithmException) {
    x25519Fallback = true
    null
  } catch (e: InvalidKeySpecException) {
    null
  } catch (e: InvalidKeyException) {
    null
  } catch (e: IllegalStateException) {
    null
  }
}

internal fun ed25519PublicKeyFromPrivateNative(secretKey: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsEd25519() == true) {
    return provider.ed25519PublicKeyFromPrivate(secretKey)
  }
  if (ed25519Fallback) return null
  return try {
    val keyFactory = KeyFactory.getInstance("Ed25519")
    val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(buildPkcs8Private(secretKey)))
    val x509Spec = keyFactory.getKeySpec(privateKey, X509EncodedKeySpec::class.java)
    x509Spec.encoded.copyOfRange(X509_PREFIX_LEN, X509_PREFIX_LEN + KEY_LEN)
  } catch (e: NoSuchAlgorithmException) {
    ed25519Fallback = true
    null
  } catch (e: InvalidKeySpecException) {
    null
  }
}

internal fun ed25519SignNative(secretKey: ByteArray, message: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsEd25519() == true) {
    return provider.ed25519Sign(secretKey, message)
  }
  if (ed25519Fallback) return null
  return try {
    val keyFactory = KeyFactory.getInstance("Ed25519")
    val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(buildPkcs8Private(secretKey)))
    val signature = Signature.getInstance("Ed25519")
    signature.initSign(privateKey)
    signature.update(message)
    signature.sign()
  } catch (e: NoSuchAlgorithmException) {
    ed25519Fallback = true
    null
  } catch (e: InvalidKeySpecException) {
    null
  }
}

internal fun ed25519VerifyNative(
    publicKey: ByteArray,
    message: ByteArray,
    signature: ByteArray,
): Boolean? {
  val provider = cryptoProvider
  if (provider?.supportsEd25519() == true) {
    return provider.ed25519Verify(publicKey, message, signature)
  }
  if (ed25519Fallback) return null
  return try {
    val keyFactory = KeyFactory.getInstance("Ed25519")
    val publicKeySpec = X509EncodedKeySpec(buildX509Public(publicKey))
    val pubKey = keyFactory.generatePublic(publicKeySpec)
    val sig = Signature.getInstance("Ed25519")
    sig.initVerify(pubKey)
    sig.update(message)
    sig.verify(signature)
  } catch (e: NoSuchAlgorithmException) {
    ed25519Fallback = true
    null
  } catch (e: SignatureException) {
    null
  } catch (e: InvalidKeySpecException) {
    null
  }
}

internal fun chacha20Poly1305EncryptWithNonceNative(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    plaintext: ByteArray,
): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsChaCha20Poly1305() == true) {
    return provider.chacha20Poly1305Encrypt(key, nonce, aad, plaintext)
  }
  if (chacha20Poly1305Fallback) return null
  require(key.size == ChaCha20Poly1305PureK.KEY_SIZE) {
    "key must be ${ChaCha20Poly1305PureK.KEY_SIZE} bytes"
  }
  require(nonce.size == ChaCha20Poly1305PureK.NONCE_SIZE) {
    "nonce must be ${ChaCha20Poly1305PureK.NONCE_SIZE} bytes"
  }
  return try {
    val cipher = Cipher.getInstance("ChaCha20-Poly1305")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
    if (aad.isNotEmpty()) cipher.updateAAD(aad)
    cipher.doFinal(plaintext)
  } catch (e: NoSuchAlgorithmException) {
    chacha20Poly1305Fallback = true
    null
  }
}

internal fun chacha20Poly1305DecryptWithNonceNative(
    key: ByteArray,
    nonce: ByteArray,
    aad: ByteArray,
    ciphertextWithTag: ByteArray,
): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsChaCha20Poly1305() == true) {
    return provider.chacha20Poly1305Decrypt(key, nonce, aad, ciphertextWithTag)
  }
  if (chacha20Poly1305Fallback) return null
  require(key.size == ChaCha20Poly1305PureK.KEY_SIZE) {
    "key must be ${ChaCha20Poly1305PureK.KEY_SIZE} bytes"
  }
  require(nonce.size == ChaCha20Poly1305PureK.NONCE_SIZE) {
    "nonce must be ${ChaCha20Poly1305PureK.NONCE_SIZE} bytes"
  }
  return try {
    val cipher = Cipher.getInstance("ChaCha20-Poly1305")
    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
    if (aad.isNotEmpty()) cipher.updateAAD(aad)
    cipher.doFinal(ciphertextWithTag)
  } catch (e: NoSuchAlgorithmException) {
    chacha20Poly1305Fallback = true
    null
  } catch (e: AEADBadTagException) {
    null
  }
}

internal fun chacha20Poly1305EncryptNative(key: ByteArray, message: ByteArray): ByteArray? {
  val nonce = randomBytes(ChaCha20Poly1305PureK.NONCE_SIZE)
  val cipherWithTag =
      chacha20Poly1305EncryptWithNonceNative(key, nonce, ByteArray(0), message) ?: return null
  return nonce + cipherWithTag
}

internal fun chacha20Poly1305DecryptNative(key: ByteArray, ciphertext: ByteArray): ByteArray? {
  if (ciphertext.size < ChaCha20Poly1305PureK.NONCE_SIZE + ChaCha20Poly1305PureK.TAG_SIZE)
      return null
  val nonce = ciphertext.copyOfRange(0, ChaCha20Poly1305PureK.NONCE_SIZE)
  val cipherWithTag = ciphertext.copyOfRange(ChaCha20Poly1305PureK.NONCE_SIZE, ciphertext.size)
  return chacha20Poly1305DecryptWithNonceNative(key, nonce, ByteArray(0), cipherWithTag)
}

internal fun sha256Native(message: ByteArray): ByteArray? {
  if (sha256Fallback) return null
  return try {
    MessageDigest.getInstance("SHA-256").digest(message)
  } catch (e: NoSuchAlgorithmException) {
    sha256Fallback = true
    null
  }
}

internal fun sha512Native(message: ByteArray): ByteArray? {
  if (sha512Fallback) return null
  return try {
    MessageDigest.getInstance("SHA-512").digest(message)
  } catch (e: NoSuchAlgorithmException) {
    sha512Fallback = true
    null
  }
}

internal fun hmacSha256Native(key: ByteArray, message: ByteArray): ByteArray? {
  if (hmacSha256Fallback) return null
  return try {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    mac.doFinal(message)
  } catch (e: NoSuchAlgorithmException) {
    hmacSha256Fallback = true
    null
  } catch (e: InvalidKeyException) {
    null
  } catch (e: IllegalArgumentException) {
    null
  }
}

internal fun hmacSha256VerifyNative(
    key: ByteArray,
    message: ByteArray,
    tag: ByteArray,
): Boolean? {
  if (hmacSha256Fallback) return null
  return try {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    val computed = mac.doFinal(message)
    var difference = computed.size xor tag.size
    val compareLength = minOf(computed.size, tag.size)
    for (index in 0 until compareLength) {
      difference = difference or (computed[index].toInt() xor tag[index].toInt())
    }
    difference == 0
  } catch (e: NoSuchAlgorithmException) {
    hmacSha256Fallback = true
    null
  } catch (e: InvalidKeyException) {
    null
  } catch (e: IllegalArgumentException) {
    null
  }
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) — native HMAC (platform JCA) → PureK fallback
// ---------------------------------------------------------------------------

private const val HKDF_HASH_LEN = 32

internal fun hkdfSha256Native(
    ikm: ByteArray,
    salt: ByteArray,
    info: ByteArray,
    outputLength: Int,
): ByteArray? {
  val prk = hkdfSha256ExtractNative(ikm, salt) ?: return null
  return hkdfSha256ExpandNative(prk, info, outputLength)
}

internal fun hkdfSha256ExtractNative(ikm: ByteArray, salt: ByteArray): ByteArray? =
    hmacSha256Native(if (salt.isEmpty()) ByteArray(HKDF_HASH_LEN) else salt, ikm)

internal fun hkdfSha256ExpandNative(
    prk: ByteArray,
    info: ByteArray,
    outputLength: Int,
): ByteArray? {
  return try {
    // RFC 5869 §2.3: L must not exceed 255*HashLen (255*32 = 8160).
    // Returning null triggers PureK fallback, which throws IllegalArgumentException.
    if (outputLength < 0 || outputLength > 255 * HKDF_HASH_LEN) return null
    val hashLength = HKDF_HASH_LEN
    val blockCount = (outputLength + hashLength - 1) / hashLength
    val output = ByteArray(outputLength)
    var previousBlock = ByteArray(0)
    for (blockNumber in 1..blockCount) {
      val message = buildExpandMessage(previousBlock, info, blockNumber)
      previousBlock = hmacSha256Native(prk, message) ?: return null
      val startOffset = (blockNumber - 1) * hashLength
      val copyLength = minOf(hashLength, outputLength - startOffset)
      previousBlock.copyInto(output, startOffset, 0, copyLength)
    }
    output
  } catch (e: NoSuchAlgorithmException) {
    null
  }
}

// ---------------------------------------------------------------------------
// HKDF-Expand block message construction (RFC 5869 §2.3: T(i) = HMAC(H, T(i-1) | info | 2^{8i}))
// ---------------------------------------------------------------------------

private fun buildExpandMessage(
    previousBlock: ByteArray,
    info: ByteArray,
    blockNumber: Int,
): ByteArray = previousBlock + info + byteArrayOf(blockNumber.toByte())

// ---------------------------------------------------------------------------
// Ed25519 ASN.1 encoding helpers
// ---------------------------------------------------------------------------

private fun buildPkcs8Private(rawKey: ByteArray): ByteArray {
  val result = ByteArray(PKCS8_PREFIX_LEN + rawKey.size)
  PKCS8_PREFIX.copyInto(result, 0)
  rawKey.copyInto(result, PKCS8_PREFIX_LEN)
  return result
}

private fun buildX509Public(rawKey: ByteArray): ByteArray {
  val result = ByteArray(X509_PREFIX_LEN + rawKey.size)
  X509_PREFIX.copyInto(result, 0)
  rawKey.copyInto(result, X509_PREFIX_LEN)
  return result
}

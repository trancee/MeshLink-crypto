/*
 * iOS dispatch bridge: CryptoKit provider → C-API (Security.framework) → PureK fallback.
 *
 * This file is the SINGLE place where dispatch branching lives on iOS. It contains
 * NO @Secret-annotated parameters, so the detekt ConstantTimeRule (ADR-0003) does
 * not flag the provider-selection or version-fallback branches.
 *
 * The actual objects (X25519, Ed25519, ChaCha20Poly1305, SHA256, SHA512,
 * HMAC_SHA256) stay thin: they delegate to this bridge via `elvis` and
 * fall back to *PureK on null.
 *
 * CryptoKit (Swift-only) is exposed to KMP via the CryptoProvider interface
 * injected by the consuming iOS app. When no provider is injected (or a provider
 * returns null), the bridge tries the C-API path (Security.framework — the same C
 * frameworks CryptoKit wraps internally). If the C-API is unavailable, the bridge
 * returns null and the actual falls back to PureK.
 *
 * Symbols note: kSecAttrKeyTypeX25519, kSecAttrKeyTypeEd25519,
 * kSecKeyAlgorithmECDHKeyExchangeStandardX, and
 * kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512 are Swift-only constants
 * (exported as binary symbols in Security.tbd but absent from the C headers that
 * Kotlin/Native cinterop parses). We recreate them as CFStrings via
 * CFStringCreateWithCString so the C functions (SecKeyCreateWithData, etc.) can use them.
 */
@file:OptIn(ExperimentalForeignApi::class)

package ch.trancee.meshlink.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreCrypto.CCHmac
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA512
import platform.CoreCrypto.kCCHmacAlgSHA256
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFIndexVar
import platform.CoreFoundation.CFNumberCreate
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.kCFNumberCFIndexType
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyKeyExchangeResult
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyCreateWithData
import platform.Security.SecKeyRef
import platform.Security.SecKeyVerifySignature
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPrivate
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.posix.memcpy

// --- Swift-only CFString constants (not in Kotlin/Native cinterop headers) ---

private val kSecAttrKeyTypeX25519CF: CFStringRef =
    CFStringCreateWithCString(null, "kSecAttrKeyTypeX25519", kCFStringEncodingUTF8)!!

private val kSecAttrKeyTypeEd25519CF: CFStringRef =
    CFStringCreateWithCString(null, "kSecAttrKeyTypeEd25519", kCFStringEncodingUTF8)!!

private val kSecKeyAlgorithmECDHKeyExchangeStandardXCF: CFStringRef =
    CFStringCreateWithCString(
        null,
        "kSecKeyAlgorithmECDHKeyExchangeStandardX",
        kCFStringEncodingUTF8,
    )!!

private val kSecKeyAlgorithmEdDSASignatureMessage: CFStringRef =
    CFStringCreateWithCString(
        null,
        "kSecKeyAlgorithmEdDSASignatureMessageCurve25519SHA512",
        kCFStringEncodingUTF8,
    )!!

// ---------------------------------------------------------------------------
// Public entry points (called by the thin iosMain actuals)
// ---------------------------------------------------------------------------

internal fun x25519Native(scalar: ByteArray, u: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsX25519() == true) {
    return provider.x25519(scalar, u)
  }
  return try {
    x25519SecKey(scalar, u)
  } catch (e: Exception) {
    null
  }
}

internal fun x25519DerivePublicKeyNative(scalar: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsX25519() == true) {
    return provider.x25519PublicKeyFromPrivate(scalar)
  }
  return try {
    x25519PublicKeyFromPrivateSecKey(scalar)
  } catch (e: Exception) {
    null
  }
}

internal fun ed25519PublicKeyFromPrivateNative(secretKey: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsEd25519() == true) {
    return provider.ed25519PublicKeyFromPrivate(secretKey)
  }
  return try {
    ed25519PublicKeyFromPrivateSecKey(secretKey)
  } catch (e: Exception) {
    null
  }
}

internal fun ed25519SignNative(secretKey: ByteArray, message: ByteArray): ByteArray? {
  val provider = cryptoProvider
  if (provider?.supportsEd25519() == true) {
    return provider.ed25519Sign(secretKey, message)
  }
  return try {
    ed25519SignSecKey(secretKey, message)
  } catch (e: Exception) {
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
  return try {
    ed25519VerifySecKey(publicKey, message, signature)
  } catch (e: Exception) {
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
  return null
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
  return null
}

internal fun chacha20Poly1305EncryptNative(
    key: ByteArray,
    message: ByteArray,
): ByteArray? {
  val nonce = randomBytes(ChaCha20Poly1305PureK.NONCE_SIZE)
  val cipherWithTag =
      chacha20Poly1305EncryptWithNonceNative(
          key,
          nonce,
          ByteArray(0),
          message,
      ) ?: return null
  return nonce + cipherWithTag
}

internal fun chacha20Poly1305DecryptNative(
    key: ByteArray,
    ciphertext: ByteArray,
): ByteArray? {
  val minLen = ChaCha20Poly1305PureK.NONCE_SIZE + ChaCha20Poly1305PureK.TAG_SIZE
  if (ciphertext.size < minLen) return null
  val nonce = ciphertext.copyOfRange(0, ChaCha20Poly1305PureK.NONCE_SIZE)
  val cipherWithTag = ciphertext.copyOfRange(ChaCha20Poly1305PureK.NONCE_SIZE, ciphertext.size)
  return chacha20Poly1305DecryptWithNonceNative(key, nonce, ByteArray(0), cipherWithTag)
}

// ---------------------------------------------------------------------------
// SHA-256 / SHA-512 / HMAC-SHA256 (CommonCrypto C API)
// ---------------------------------------------------------------------------

private const val SHA256_OUTPUT = 32
private const val SHA512_OUTPUT = 64
private const val HMAC_SHA256_OUTPUT = 32

internal fun sha256Native(message: ByteArray): ByteArray? {
  val digest = ByteArray(SHA256_OUTPUT)
  message.usePinned { msgPin ->
    digest.usePinned { dPin ->
      CC_SHA256(
          data = msgPin.addressOf(0),
          len = message.size.toUInt(),
          md = dPin.addressOf(0).reinterpret<UByteVar>(),
      )
    }
  }
  return digest
}

internal fun sha512Native(message: ByteArray): ByteArray? {
  val digest = ByteArray(SHA512_OUTPUT)
  message.usePinned { msgPin ->
    digest.usePinned { dPin ->
      CC_SHA512(
          data = msgPin.addressOf(0),
          len = message.size.toUInt(),
          md = dPin.addressOf(0).reinterpret<UByteVar>(),
      )
    }
  }
  return digest
}

/**
 * SHAKE256 (FIPS 202 §8.4) native dispatch.
 *
 * iOS provides no CommonCrypto or Security.framework C-API for SHAKE256. The pure-Kotlin path is
 * always taken (ADR-0001, ticket 34).
 */
internal fun shake256Native(message: ByteArray, outputLength: Int): ByteArray? = null

/**
 * SHAKE128 (FIPS 202 §8.3) native dispatch.
 *
 * iOS provides no CommonCrypto or Security.framework C-API for SHAKE128. The pure-Kotlin path is
 * always taken (ADR-0001, ticket 34).
 */
internal fun shake128Native(message: ByteArray, outputLength: Int): ByteArray? = null

internal fun hmacSha256Native(key: ByteArray, message: ByteArray): ByteArray? {
  val mac = ByteArray(HMAC_SHA256_OUTPUT)
  key.usePinned { keyPin ->
    message.usePinned { msgPin ->
      mac.usePinned { macPin ->
        CCHmac(
            kCCHmacAlgSHA256,
            keyPin.addressOf(0),
            key.size.toULong(),
            msgPin.addressOf(0),
            message.size.toULong(),
            macPin.addressOf(0),
        )
      }
    }
  }
  return mac
}

internal fun hmacSha256VerifyNative(
    key: ByteArray,
    message: ByteArray,
    tag: ByteArray,
): Boolean? {
  val computed = hmacSha256Native(key, message) ?: return null
  var difference = computed.size xor tag.size
  val compareLength = minOf(computed.size, tag.size)
  for (index in 0 until compareLength) {
    difference = difference or (computed[index].toInt() xor tag[index].toInt())
  }
  return difference == 0
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869) — native HMAC (platform CCHmac) → PureK fallback
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
  } catch (e: Exception) {
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
// X25519 — SecKeyCopyKeyExchangeResult (Security.framework, iOS 14+)
// ---------------------------------------------------------------------------

private fun x25519SecKey(
    scalar: ByteArray,
    u: ByteArray,
): ByteArray? {
  val privateKey = secKeyFromBytes(scalar, kSecAttrKeyTypeX25519CF, true) ?: return null
  val peerPublicKey =
      secKeyFromBytes(u, kSecAttrKeyTypeX25519CF, false)
          ?: run {
            CFRelease(privateKey)
            return null
          }
  val shared =
      SecKeyCopyKeyExchangeResult(
          privateKey,
          kSecKeyAlgorithmECDHKeyExchangeStandardXCF,
          peerPublicKey,
          null,
          null,
      )
          ?: run {
            CFRelease(peerPublicKey)
            CFRelease(privateKey)
            return null
          }
  val result = cfDataToBytes(shared)
  CFRelease(shared)
  CFRelease(peerPublicKey)
  CFRelease(privateKey)
  return result
}

private fun x25519PublicKeyFromPrivateSecKey(scalar: ByteArray): ByteArray? {
  val privateKey = secKeyFromBytes(scalar, kSecAttrKeyTypeX25519CF, true) ?: return null
  val publicKey =
      SecKeyCopyPublicKey(privateKey)
          ?: run {
            CFRelease(privateKey)
            return null
          }
  val extRep =
      SecKeyCopyExternalRepresentation(publicKey, null)
          ?: run {
            CFRelease(publicKey)
            CFRelease(privateKey)
            return null
          }
  val result = cfDataToBytes(extRep)
  CFRelease(extRep)
  CFRelease(publicKey)
  CFRelease(privateKey)
  return result
}

// ---------------------------------------------------------------------------
// Ed25519 — SecKeyCreateWithData + SecKeyCreateSignature / SecKeyVerifySignature
// (Security.framework, iOS 14+)
// ---------------------------------------------------------------------------

private fun ed25519PublicKeyFromPrivateSecKey(secretKey: ByteArray): ByteArray? {
  val privateKey = secKeyFromBytes(secretKey, kSecAttrKeyTypeEd25519CF, true) ?: return null
  val publicKey =
      SecKeyCopyPublicKey(privateKey)
          ?: run {
            CFRelease(privateKey)
            return null
          }
  val extRep =
      SecKeyCopyExternalRepresentation(publicKey, null)
          ?: run {
            CFRelease(publicKey)
            CFRelease(privateKey)
            return null
          }
  val result = cfDataToBytes(extRep)
  CFRelease(extRep)
  CFRelease(publicKey)
  CFRelease(privateKey)
  return result
}

private fun ed25519SignSecKey(secretKey: ByteArray, message: ByteArray): ByteArray? {
  val privateKey = secKeyFromBytes(secretKey, kSecAttrKeyTypeEd25519CF, true) ?: return null
  val msgData =
      dataToCFData(message)
          ?: run {
            CFRelease(privateKey)
            return null
          }
  val signature =
      SecKeyCreateSignature(
          privateKey,
          kSecKeyAlgorithmEdDSASignatureMessage,
          msgData,
          null,
      )
          ?: run {
            CFRelease(msgData)
            CFRelease(privateKey)
            return null
          }
  val result = cfDataToBytes(signature)
  CFRelease(signature)
  CFRelease(msgData)
  CFRelease(privateKey)
  return result
}

private fun ed25519VerifySecKey(
    publicKey: ByteArray,
    message: ByteArray,
    signature: ByteArray,
): Boolean? {
  val pubKey = secKeyFromBytes(publicKey, kSecAttrKeyTypeEd25519CF, false) ?: return null
  val msgData =
      dataToCFData(message)
          ?: run {
            CFRelease(pubKey)
            return null
          }
  val sigData =
      dataToCFData(signature)
          ?: run {
            CFRelease(msgData)
            CFRelease(pubKey)
            return null
          }
  val result =
      SecKeyVerifySignature(
          pubKey,
          kSecKeyAlgorithmEdDSASignatureMessage,
          msgData,
          sigData,
          null,
      )
  CFRelease(sigData)
  CFRelease(msgData)
  CFRelease(pubKey)
  return result
}

// ---------------------------------------------------------------------------
// SecKey helpers — create SecKeyRef from raw bytes
// ---------------------------------------------------------------------------

private fun secKeyFromBytes(
    rawKey: ByteArray,
    keyType: CFStringRef,
    isPrivate: Boolean,
): SecKeyRef? {
  val keyData = dataToCFData(rawKey) ?: return null
  // Null callbacks: CFDictionary does not retain/release its contents.
  val attrs =
      CFDictionaryCreateMutable(null, 0, null, null)
          ?: run {
            CFRelease(keyData)
            return null
          }
  CFDictionarySetValue(attrs, kSecAttrKeyType, keyType)
  CFDictionarySetValue(
      attrs,
      kSecAttrKeyClass,
      if (isPrivate) kSecAttrKeyClassPrivate else kSecAttrKeyClassPublic,
  )
  memScoped {
    val sizeVar = alloc<CFIndexVar>()
    sizeVar.value = 256L
    val sizeNum = CFNumberCreate(null, kCFNumberCFIndexType, sizeVar.ptr)
    if (sizeNum != null) {
      CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, sizeNum)
      CFRelease(sizeNum) // Dictionary has null callbacks; safe to release after add
    }
  }
  val secKey = SecKeyCreateWithData(keyData, attrs, null)
  // SecKeyCreateWithData copies the key data and attributes; safe to release.
  CFRelease(keyData)
  CFRelease(attrs)
  return secKey // Caller owns the SecKeyRef
}

// ---------------------------------------------------------------------------
// CFData helpers
// ---------------------------------------------------------------------------

private fun dataToCFData(bytes: ByteArray): CFDataRef? = bytes.usePinned { pinned ->
  CFDataCreate(null, pinned.addressOf(0).reinterpret<UByteVar>(), bytes.size.toLong())
}

private fun cfDataToBytes(cfData: CFDataRef?): ByteArray? {
  if (cfData == null) return null
  val length = CFDataGetLength(cfData).toInt()
  if (length == 0) return ByteArray(0)
  val bytes = CFDataGetBytePtr(cfData) ?: return null
  val result = ByteArray(length)
  result.usePinned { resultPin ->
    memcpy(resultPin.addressOf(0), bytes, length.toULong())
  }
  return result
}

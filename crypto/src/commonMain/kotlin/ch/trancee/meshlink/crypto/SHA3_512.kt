/*
 * SPDX-License-Identifier: Apache-2.0
 * SHA3-512 message digest (FIPS 202 §6.2).
 *
 * Pure-Kotlin Keccak-f[1600] engine: rate = 72 bytes (576 bits), capacity = 128 bytes (1024 bits),
 * domain separation suffix 0x06, pad10*1 padding (0x80 in the last rate byte), fixed 64-byte output.
 * All 64-bit lane arithmetic uses Kotlin [Long]; XOR absorbs and extracts bytes in little-endian lane
 * order.
 *
 * The permutation uses 24 fixed rounds with no data-dependent branching or indexing, so execution
 * time is independent of message content (ADR-0001, ADR-0003). The `@Secret` annotation on [digest]
 * lets the `:crypto-detekt-rules` `ConstantTimeRule` statically reject any data-dependent `if`/`when`
 * or secret-indexed array access in this file.
 *
 * SHA3-512 can be built on the existing keccakF1600 permutation in KeccakEngine.kt with a one-line
 * change: the domain-separation suffix changes from 0x1F (SHAKE) to 0x06 (SHA3). The pad10*1
 * termination is identical. No native SHA3 API accessible via cinterop exists on iOS (CryptoKit is
 * Swift-only, corecrypto SHA3 is private); JVM JCA (JDK 9+) and Android (API 28+ Conscrypt) provide
 * native SHA3-512 via the dispatch bridge (ADR-0001, ADR-0002).
 */
package ch.trancee.meshlink.crypto

/** Rate block size for SHA3-512: 72 bytes = 576 bits (FIPS 202 §6.2). */
internal const val SHA3_512_RATE = 72

/**
 * SHA3-512 message digest (FIPS 202 §6.2).
 *
 * Pure-Kotlin Keccak-f[1600] engine using the shared [keccakF1600] permutation. Rate = 72 bytes
 * (576 bits), capacity = 128 bytes (1024 bits), domain separation suffix 0x06, pad10*1 padding,
 * fixed 64-byte output.
 */
internal object SHA3_512PureK {

  /** Output digest length for SHA3-512: 64 bytes = 512 bits (FIPS 202 §6.2). */
  internal const val OUTPUT_LENGTH = 64

  /**
   * Computes SHA3-512 of [message], producing a 64-byte digest.
   *
   * @param message the (possibly secret) bytes to hash.
   * @return the 64-byte SHA3-512 digest.
   */
  fun digest(@Secret message: ByteArray): ByteArray {
    val hasher = SHA3_512Hasher()
    hasher.update(message, 0, message.size)
    return hasher.digest()
  }
}

/**
 * Incremental SHA3-512 hasher (FIPS 202 §6.2) for internal composition.
 *
 * Holds mutable Keccak state across [update] calls and finalises via [digest], which applies the
 * SHA3-512 domain-suffix byte (0x06) and pad10*1 (0x80) and returns the fixed 64-byte output. Since
 * the output fits within a single rate block (64 < 72), no multi-block squeeze is needed.
 *
 * Constant-time discipline is inherited from the public API's `@Secret` annotation: no
 * data-dependent branch or indexing touches secret material (ADR-0003).
 */
internal class SHA3_512Hasher {

  /** 25 x 64-bit lanes (1600 bits), initialised to zero. */
  private val state = LongArray(25)

  /** Leftover bytes from the previous block, buffered until a full rate block is available. */
  private val buffer = ByteArray(SHA3_512_RATE)

  private var bufferLen = 0

  private var finalized = false

  /**
   * Feeds [length] bytes of [data] starting at [offset] into the sponge.
   *
   * Data is accumulated in a [SHA3_512_RATE]-byte block buffer; whenever a full rate block is ready
   * it is XORed into the state and Keccak-f[1600] is applied. Remaining bytes stay buffered for the
   * next call or the final [digest].
   */
  fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
    check(!finalized) { "hasher already finalized" }
    var pos = offset
    var remaining = length
    while (remaining > 0) {
      val toCopy = minOf(remaining, SHA3_512_RATE - bufferLen)
      data.copyInto(buffer, bufferLen, pos, pos + toCopy)
      bufferLen += toCopy
      pos += toCopy
      remaining -= toCopy
      if (bufferLen == SHA3_512_RATE) {
        absorbBlock(buffer)
        bufferLen = 0
      }
    }
  }

  /**
   * Finalises the sponge: appends the SHA3-512 domain-suffix byte (0x06) and pad10*1 (0x80 at the
   * last rate byte), absorbs the padded block, then squeezes 64 bytes from the rate portion.
   */
  fun digest(): ByteArray {
    check(!finalized) { "hasher already finalized" }
    // Zero stale data beyond the buffered message
    for (i in bufferLen until SHA3_512_RATE) buffer[i] = 0
    // Domain-separation suffix 0x06 (2-bit "01" for SHA3) + pad10*1 (0x80)
    buffer[bufferLen] = 0x06.toByte()
    buffer[SHA3_512_RATE - 1] = (buffer[SHA3_512_RATE - 1].toInt() xor 0x80).toByte()
    // Absorb the padded block
    absorbBlock(buffer)
    finalized = true
    // Squeeze 64 bytes from the rate portion (fits in one block, no keccakF1600 needed)
    return squeeze(SHA3_512PureK.OUTPUT_LENGTH)
  }

  /**
   * Extracts [outputLength] bytes from the rate portion of the state. SHA3-512 output (64 bytes)
   * always fits within a single rate block (72 bytes), so no multi-block squeeze or padding of the
   * squeeze is needed.
   */
  private fun squeeze(outputLength: Int): ByteArray {
    val result = ByteArray(outputLength)
    for (i in 0 until outputLength) {
      val lane = i / 8
      val byteOffset = i % 8
      result[i] = (state[lane] ushr (byteOffset * 8)).toByte()
    }
    return result
  }

  /**
   * XORs [block] ([SHA3_512_RATE] bytes / 9 lanes) into the rate portion of the state and applies
   * the full Keccak-f[1600] permutation from [KeccakEngine.kt].
   */
  private fun absorbBlock(block: ByteArray) {
    for (lane in 0 until SHA3_512_RATE / 8) {
      val base = lane * 8
      var value = 0L
      for (byte in 0 until 8) {
        value = value or ((block[base + byte].toLong() and 0xFFL) shl (byte * 8))
      }
      state[lane] = state[lane] xor value
    }
    keccakF1600(state)
  }
}

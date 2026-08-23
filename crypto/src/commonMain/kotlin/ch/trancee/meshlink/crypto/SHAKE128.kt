/*
 * SPDX-License-Identifier: Apache-2.0
 * SHAKE128 extendable-output function (FIPS 202 §8.3).
 *
 * Pure-Kotlin Keccak-f[1600] engine: rate = 168 bytes (1344 bits), capacity = 32 bytes (256 bits),
 * domain separation suffix 0x1F, pad10*1 padding (0x80 in the last rate byte). All 64-bit lane
 * arithmetic uses Kotlin [Long]; XOR absorbs and extracts bytes in little-endian lane order.
 *
 * The permutation uses 24 fixed rounds with no data-dependent branching or indexing, so execution
 * time is independent of message content (ADR-0001, ADR-0003). The `@Secret` annotation on [digest]
 * lets the `:crypto-detekt-rules` `ConstantTimeRule` statically reject any data-dependent
 * `if`/`when` or secret-indexed array access in this file.
 *
 * No native SHAKE128 API exists on JDK 21 (JCA has no SHAKE in the supported provider set for this
 * library), Android API 21+, or iOS CommonCrypto / Security.framework — the pure-Kotlin path is the
 * only implementation (ADR-0001, ticket 34).
 */
package ch.trancee.meshlink.crypto

/** Rate block size for SHAKE128: 168 bytes = 1344 bits (FIPS 202 §8.3). */
internal const val SHAKE128_RATE = 168

/**
 * SHAKE128 extendable-output function (FIPS 202 §8.3).
 *
 * Pure-Kotlin Keccak-f[1600] engine using the shared [keccakF1600] permutation. Rate = 168 bytes
 * (1344 bits), capacity = 32 bytes (256 bits), domain separation suffix 0x1F, pad10*1 padding.
 */
internal object SHAKE128PureK {

  /**
   * Computes SHAKE128 of [message], producing [outputLength] bytes of output.
   *
   * @param message the (possibly secret) bytes to hash.
   * @param outputLength the number of output bytes to squeeze (any positive value).
   * @return `[outputLength]` pseudo-random bytes derived from the message.
   */
  fun digest(@Secret message: ByteArray, outputLength: Int): ByteArray {
    val hasher = SHAKE128Hasher()
    hasher.update(message, 0, message.size)
    return hasher.digest(outputLength)
  }
}

/**
 * Incremental SHAKE128 hasher (FIPS 202 §8.3) for internal composition.
 *
 * Holds mutable Keccak state across [update] calls and finalises via [digest], which applies the
 * pad10*1 domain-separation padding and squeezes the requested number of output bytes (multiple
 * Keccak-f[1600] calls if the output spans more than one rate block).
 *
 * Constant-time discipline is inherited from the public API's `@Secret` annotation: no
 * data-dependent branch or indexing touches secret material (ADR-0003).
 */
internal class SHAKE128Hasher {

  /** 25 x 64-bit lanes (1600 bits), initialised to zero. */
  private val state = LongArray(25)

  /** Leftover bytes from the previous block, buffered until a full rate block is available. */
  private val buffer = ByteArray(SHAKE128_RATE)

  private var bufferLen = 0

  /**
   * Feeds [length] bytes of [data] starting at [offset] into the sponge.
   *
   * Data is accumulated in a [SHAKE128_RATE]-byte block buffer; whenever a full rate block is ready
   * it is XORed into the state and Keccak-f[1600] is applied. Remaining bytes stay buffered for the
   * next call or the final [digest].
   */
  fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
    var pos = offset
    var remaining = length
    while (remaining > 0) {
      val toCopy = minOf(remaining, SHAKE128_RATE - bufferLen)
      data.copyInto(buffer, bufferLen, pos, pos + toCopy)
      bufferLen += toCopy
      pos += toCopy
      remaining -= toCopy
      if (bufferLen == SHAKE128_RATE) {
        absorbBlock(buffer)
        bufferLen = 0
      }
    }
  }

  /**
   * Finalises the sponge: appends the SHAKE128 domain-suffix byte (0x1F) and pad10*1 (0x80 at the
   * last rate byte), absorbs the padded block, then squeezes [outputLength] bytes.
   *
   * The hasher must not be used after this call.
   */
  fun digest(outputLength: Int): ByteArray {
    // --- Step 1: zero stale data beyond the buffered message --------------
    for (i in bufferLen until SHAKE128_RATE) buffer[i] = 0

    // --- Step 2: domain-separation suffix 0x1F + pad10*1 (0x80) -----------
    buffer[bufferLen] = 0x1F.toByte()
    buffer[SHAKE128_RATE - 1] = (buffer[SHAKE128_RATE - 1].toInt() xor 0x80).toByte()

    // --- Step 3: absorb the padded block -----------------------------------
    absorbBlock(buffer)

    // --- Step 4: squeeze output (multi-block if needed) --------------------
    val result = ByteArray(outputLength)
    var produced = 0
    while (produced < outputLength) {
      val chunk = minOf(outputLength - produced, SHAKE128_RATE)
      for (i in 0 until chunk) {
        val lane = i / 8
        val byteOffset = i % 8
        result[produced + i] = (state[lane] ushr (byteOffset * 8)).toByte()
      }
      produced += chunk
      if (produced < outputLength) keccakF1600(state)
    }
    return result
  }

  /**
   * XORs [block] ([SHAKE128_RATE] bytes / 21 lanes) into the rate portion of the state and applies
   * the full Keccak-f[1600] permutation from [KeccakEngine.kt].
   */
  private fun absorbBlock(block: ByteArray) {
    for (lane in 0 until SHAKE128_RATE / 8) {
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

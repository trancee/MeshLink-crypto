/*
 * SPDX-License-Identifier: Apache-2.0
 * SHAKE256 extendable-output function (FIPS 202 §8.4).
 *
 * Pure-Kotlin Keccak-f[1600] engine: rate = 136 bytes (1088 bits), capacity = 64 bytes (512 bits),
 * domain separation suffix 0x1F, pad10*1 padding (0x80 in the last rate byte). All 64-bit lane
 * arithmetic uses Kotlin [Long]; XOR absorbs and extracts bytes in little-endian lane order.
 *
 * The permutation uses 24 fixed rounds with no data-dependent branching or indexing, so execution
 * time is independent of message content (ADR-0001, ADR-0003). The `@Secret` annotation on [digest]
 * lets the `:crypto-detekt-rules` `ConstantTimeRule` statically reject any data-dependent
 * `if`/`when` or secret-indexed array access in this file.
 *
 * No native SHAKE256 API exists on JDK 21 (JCA has no SHAKE in the supported provider set for this
 * library), Android API 21+, or iOS CommonCrypto / Security.framework — the pure-Kotlin path is the
 * only implementation (ADR-0001, ticket 34).
 */
package ch.trancee.meshlink.crypto

/** Rate block size for SHAKE256: 136 bytes = 1088 bits (FIPS 202 §8.4). */
internal const val SHAKE256_RATE = 136

/**
 * SHAKE256 extendable-output function (FIPS 202 §8.4).
 *
 * Pure-Kotlin Keccak-f[1600] engine using the shared [keccakF1600] permutation. Rate = 136 bytes
 * (1088 bits), capacity = 64 bytes (512 bits), domain separation suffix 0x1F, pad10*1 padding.
 */
internal object SHAKE256PureK {

  /**
   * Computes SHAKE256 of [message], producing [outputLength] bytes of output.
   *
   * @param message the (possibly secret) bytes to hash.
   * @param outputLength the number of output bytes to squeeze (any positive value).
   * @return `[outputLength]` pseudo-random bytes derived from the message.
   */
  fun digest(@Secret message: ByteArray, outputLength: Int): ByteArray {
    val hasher = SHAKE256Hasher()
    hasher.update(message, 0, message.size)
    return hasher.digest(outputLength)
  }
}

/**
 * Incremental SHAKE256 hasher (FIPS 202 §8.4) for internal composition.
 *
 * Holds mutable Keccak state across [update] calls and finalises via [digest], which applies the
 * pad10*1 domain-separation padding and squeezes the requested number of output bytes (multiple
 * Keccak-f[1600] calls if the output spans more than one rate block).
 *
 * The [finalize] / [squeeze] pair enables incremental squeezing after finalization — required by
 * ML-DSA sampling routines that consume blocks one at a time through rejection sampling.
 *
 * Constant-time discipline is inherited from the public API's `@Secret` annotation: no
 * data-dependent branch or indexing touches secret material (ADR-0003).
 */
internal class SHAKE256Hasher {

  /** 25 x 64-bit lanes (1600 bits), initialised to zero. */
  private val state = LongArray(25)

  /** Leftover bytes from the previous block, buffered until a full rate block is available. */
  private val buffer = ByteArray(SHAKE256_RATE)

  private var bufferLen = 0

  private var finalized = false

  /** Whether the current permutation state has already been (partially) squeezed. */
  private var squeezed = false

  /**
   * Feeds [length] bytes of [data] starting at [offset] into the sponge.
   *
   * Data is accumulated in a [SHAKE256_RATE]-byte block buffer; whenever a full rate block is ready
   * it is XORed into the state and Keccak-f[1600] is applied. Remaining bytes stay buffered for the
   * next call or the final [digest].
   */
  fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
    check(!finalized) { "hasher already finalized" }
    var pos = offset
    var remaining = length
    while (remaining > 0) {
      val toCopy = minOf(remaining, SHAKE256_RATE - bufferLen)
      data.copyInto(buffer, bufferLen, pos, pos + toCopy)
      bufferLen += toCopy
      pos += toCopy
      remaining -= toCopy
      if (bufferLen == SHAKE256_RATE) {
        absorbBlock(buffer)
        bufferLen = 0
      }
    }
  }

  /**
   * Finalises the sponge: appends the SHAKE256 domain-suffix byte (0x1F) and pad10*1 (0x80 at the
   * last rate byte), absorbs the padded block. Must be called before [squeeze].
   */
  fun finalize() {
    check(!finalized) { "hasher already finalized" }
    for (i in bufferLen until SHAKE256_RATE) buffer[i] = 0
    buffer[bufferLen] = 0x1F.toByte()
    buffer[SHAKE256_RATE - 1] = (buffer[SHAKE256_RATE - 1].toInt() xor 0x80).toByte()
    absorbBlock(buffer)
    finalized = true
  }

  /**
   * Squeezes [outputLength] bytes from the sponge after [finalize] has been called. Can be called
   * multiple times to squeeze incrementally.
   */
  fun squeeze(outputLength: Int): ByteArray {
    check(finalized) { "hasher not finalized" }
    val result = ByteArray(outputLength)
    var produced = 0
    while (produced < outputLength) {
      if (squeezed) keccakF1600(state)
      val chunk = minOf(outputLength - produced, SHAKE256_RATE)
      for (i in 0 until chunk) {
        val lane = i / 8
        val byteOffset = i % 8
        result[produced + i] = (state[lane] ushr (byteOffset * 8)).toByte()
      }
      produced += chunk
      squeezed = true
    }
    return result
  }

  /**
   * Finalises the sponge and squeezes [outputLength] bytes in one call. Convenience method
   * equivalent to `finalize(); squeeze(outputLength)`.
   */
  fun digest(outputLength: Int): ByteArray {
    finalize()
    return squeeze(outputLength)
  }

  /**
   * XORs [block] ([SHAKE256_RATE] bytes / 17 lanes) into the rate portion of the state and applies
   * the full Keccak-f[1600] permutation from [KeccakEngine.kt].
   */
  private fun absorbBlock(block: ByteArray) {
    for (lane in 0 until SHAKE256_RATE / 8) {
      val base = lane * 8
      var value = 0L
      for (byte in 0 until 8) {
        value = value or ((block[base + byte].toLong() and 0xFFL) shl (byte * 8))
      }
      state[lane] = state[lane] xor value
    }
    keccakF1600(state)
    squeezed = false
  }
}

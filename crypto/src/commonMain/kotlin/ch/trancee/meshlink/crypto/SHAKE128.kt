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
 *
 * The one-shot [digest] function absorbs full rate blocks directly from the message without going
 * through the [SHAKE128Hasher] object, eliminating per-call object allocation and virtual dispatch
 * overhead for the common case of hashing a complete message in one call.
 *
 * Platform-optimized byte conversion: `leBytesToLong` / `longToLEBytes` use `java.nio.ByteBuffer`
 * on JVM/Android (zero-copy view, no Unsafe), and manual shl/or/and chains on iOS.
 */
internal object SHAKE128PureK {

  /**
   * Computes SHAKE128 of [message], producing [outputLength] bytes of output.
   *
   * Absorbs full rate blocks directly from the message (skipping buffer copy), applies pad10*1
   * padding, then squeezes the requested output. Uses platform-optimized [leBytesToLong] /
   * [longToLEBytes] for byte-level I/O (ByteBuffer on JVM).
   *
   * @param message the (possibly secret) bytes to hash.
   * @param outputLength the number of output bytes to squeeze (any positive value).
   * @return `[outputLength]` pseudo-random bytes derived from the message.
   */
  fun digest(@Secret message: ByteArray, outputLength: Int): ByteArray {
    val rateLanes = SHAKE128_RATE / 8 // 21
    val state = LongArray(25)

    // Absorb full rate blocks directly from the message, skipping buffer copy
    var pos = 0
    var remaining = message.size
    while (remaining >= SHAKE128_RATE) {
      for (lane in 0 until rateLanes) {
        val b = pos + lane * 8
        state[lane] = state[lane] xor leBytesToLong(message, b)
      }
      keccakF1600(state)
      pos += SHAKE128_RATE
      remaining -= SHAKE128_RATE
    }

    // Final block: copy remaining bytes, apply padding, absorb
    val padded = ByteArray(SHAKE128_RATE)
    message.copyInto(padded, 0, pos, pos + remaining)
    padded[remaining] = 0x1F.toByte()
    padded[SHAKE128_RATE - 1] = (padded[SHAKE128_RATE - 1].toInt() xor 0x80).toByte()
    for (lane in 0 until rateLanes) {
      val b = lane * 8
      state[lane] = state[lane] xor leBytesToLong(padded, b)
    }
    keccakF1600(state)

    // Squeeze output
    val result = ByteArray(outputLength)
    var produced = 0
    while (produced < outputLength) {
      if (produced > 0) keccakF1600(state)
      val chunk = minOf(outputLength - produced, SHAKE128_RATE)
      var lane = 0
      while (lane < chunk / 8) {
        val off = produced + lane * 8
        longToLEBytes(state[lane], result, off)
        lane++
      }
      // Handle remaining bytes when chunk is not a multiple of 8
      val remStart = lane * 8
      for (i in remStart until chunk) {
        result[produced + i] = (state[i / 8] ushr ((i % 8) * 8)).toByte()
      }
      produced += chunk
    }
    return result
  }
}

/**
 * Incremental SHAKE128 hasher (FIPS 202 §8.3) for internal composition.
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
internal class SHAKE128Hasher {

  /** 25 x 64-bit lanes (1600 bits), initialised to zero. */
  private val state = LongArray(25)

  /** Leftover bytes from the previous block, buffered until a full rate block is available. */
  private val buffer = ByteArray(SHAKE128_RATE)

  private var bufferLen = 0

  private var finalized = false

  /**
   * Feeds [length] bytes of [data] starting at [offset] into the sponge.
   *
   * Data is accumulated in a [SHAKE128_RATE]-byte block buffer; whenever a full rate block is ready
   * it is XORed into the state and Keccak-f[1600] is applied. Remaining bytes stay buffered for the
   * next call or the final [digest].
   */
  fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
    check(!finalized) { "hasher already finalized" }
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
   * last rate byte), absorbs the padded block. Must be called before [squeeze].
   */
  fun finalize() {
    check(!finalized) { "hasher already finalized" }
    // Zero stale data beyond the buffered message
    for (i in bufferLen until SHAKE128_RATE) buffer[i] = 0
    // Domain-separation suffix 0x1F + pad10*1 (0x80)
    buffer[bufferLen] = 0x1F.toByte()
    buffer[SHAKE128_RATE - 1] = (buffer[SHAKE128_RATE - 1].toInt() xor 0x80).toByte()
    // Absorb the padded block
    absorbBlock(buffer)
    finalized = true
  }

  /**
   * Squeezes [outputLength] bytes from the sponge after [finalize] has been called. If output spans
   * more than one rate block, the Keccak-f[1600] permutation is applied between blocks. Can be
   * called multiple times to squeeze incrementally.
   */
  fun squeeze(outputLength: Int): ByteArray {
    check(finalized) { "hasher not finalized" }
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
   * Finalises the sponge and squeezes [outputLength] bytes in one call. Convenience method
   * equivalent to `finalize(); squeeze(outputLength)`.
   */
  fun digest(outputLength: Int): ByteArray {
    finalize()
    return squeeze(outputLength)
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

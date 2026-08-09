/*
 * ChaCha20 stream cipher core (RFC 8439 §2.3).
 *
 * Pure-Kotlin, constant-time implementation of the quarter round, double round
 * (10 iterations × 8 quarter rounds = 20 rounds), and single-block keystream function.
 * The counter is supplied by the caller — the AEAD layer ([ChaCha20Poly1305])
 * derives the MAC-key block at counter 0 and the encryption stream from counter 1.
 *
 * No BigInteger, no platform crypto. Integer arithmetic uses signed [Int] wrapping
 * (mod 2^32), matching the reference in `tink-java`'s ChaCha20Util.
 */
package ch.trancee.meshlink.crypto

/** ChaCha20 quarter round, double round, and keystream block primitives (RFC 8439 §2.3). */
internal object ChaCha20 {

  /** ChaCha20 constant words: "expand 32-byte k" in little-endian (RFC 8439 §2.3). */
  private val sigma: IntArray = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

  /** Keystream block size in bytes (64 = 16 words × 4 bytes). */
  internal const val BLOCK_SIZE: Int = 64

  /** Key size in bytes (32 = 256 bits). */
  internal const val KEY_SIZE: Int = 32

  /** Nonce size in bytes (12 = 96 bits). */
  internal const val NONCE_SIZE: Int = 12

  // ------------------------------------------------------------------
  // LE byte / int conversion helpers (shared with Poly1305)
  // ------------------------------------------------------------------

  /** Loads a 32-bit little-endian integer from [bytes] at [offset]. */
  internal fun load32LE(bytes: ByteArray, offset: Int): Int =
      (bytes[offset].toInt() and 0xFF) or
          ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
          ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
          ((bytes[offset + 3].toInt() and 0xFF) shl 24)

  /** Stores [value] into [bytes] at [offset] as a 32-bit little-endian integer. */
  internal fun store32LE(bytes: ByteArray, offset: Int, value: Int) {
    bytes[offset] = (value and 0xFF).toByte()
    bytes[offset + 1] = (value ushr 8 and 0xFF).toByte()
    bytes[offset + 2] = (value ushr 16 and 0xFF).toByte()
    bytes[offset + 3] = (value ushr 24 and 0xFF).toByte()
  }

  /** Stores [value] into [bytes] at [offset] as a 64-bit little-endian integer. */
  internal fun store64LE(bytes: ByteArray, offset: Int, value: Long) {
    bytes[offset] = (value and 0xFFL).toByte()
    bytes[offset + 1] = (value ushr 8 and 0xFFL).toByte()
    bytes[offset + 2] = (value ushr 16 and 0xFFL).toByte()
    bytes[offset + 3] = (value ushr 24 and 0xFFL).toByte()
    bytes[offset + 4] = (value ushr 32 and 0xFFL).toByte()
    bytes[offset + 5] = (value ushr 40 and 0xFFL).toByte()
    bytes[offset + 6] = (value ushr 48 and 0xFFL).toByte()
    bytes[offset + 7] = (value ushr 56 and 0xFFL).toByte()
  }

  // ------------------------------------------------------------------
  // Block function (RFC 8439 §2.3)
  // ------------------------------------------------------------------

  /**
   * Computes one 64-byte ChaCha20 keystream block for [key], [nonce], and [counter].
   *
   * The initial state matrix is set:
   * - words 0–3 = sigma constants
   * - words 4–11 = key (8 × 32-bit LE)
   * - word 12 = counter (32-bit, LE)
   * - words 13–15 = nonce (3 × 32-bit LE)
   *
   * After 20 rounds, the working state is added to the initial state (mod 2^32) and serialized as
   * 64 little-endian bytes.
   *
   * @param key 32-byte key.
   * @param counter 32-bit block counter value.
   * @param nonce 12-byte nonce.
   * @return 64-byte keystream block.
   */
  internal fun block(@Secret key: ByteArray, counter: Int, nonce: ByteArray): ByteArray {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }

    // Initialise state matrix.
    val state = IntArray(16)
    sigma.copyInto(state, 0)
    for (i in 0 until 8) {
      state[4 + i] = load32LE(key, i * 4)
    }
    state[12] = counter
    for (i in 0 until 3) {
      state[13 + i] = load32LE(nonce, i * 4)
    }

    // Working state = copy of initial state, then 20 rounds.
    val working = state.copyOf()
    shuffleState(working)

    // Add initial state to working state (mod 2^32, wrapping).
    for (i in 0 until 16) {
      working[i] += state[i]
    }

    // Serialize to 64 bytes (little-endian).
    val out = ByteArray(BLOCK_SIZE)
    for (i in 0 until 16) {
      store32LE(out, i * 4, working[i])
    }
    return out
  }

  /**
   * XORs [data] with the ChaCha20 keystream starting at [initialCounter]. Encryption and decryption
   * are the same operation (XOR with keystream).
   *
   * @param key 32-byte key.
   * @param nonce 12-byte nonce.
   * @param initialCounter starting counter value (1 for encryption in AEAD, 0 for MAC-key block).
   * @param data plaintext (encrypt) or ciphertext (decrypt).
   * @return XORed output, same length as [data].
   */
  internal fun streamXor(
      @Secret key: ByteArray,
      nonce: ByteArray,
      initialCounter: Int,
      data: ByteArray,
  ): ByteArray {
    require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes" }
    require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes" }

    if (data.isEmpty()) return ByteArray(0)

    val output = ByteArray(data.size)
    var offset = 0
    var counter = initialCounter
    while (offset < data.size) {
      val keystream = block(key, counter, nonce)
      val chunk = minOf(BLOCK_SIZE, data.size - offset)
      for (i in 0 until chunk) {
        output[offset + i] = (data[offset + i].toInt() xor keystream[i].toInt()).toByte()
      }
      offset += chunk
      counter = (counter + 1)
    }
    return output
  }

  // ------------------------------------------------------------------
  // Round functions (RFC 8439 §2.1)
  // ------------------------------------------------------------------

  /**
   * Quarter round: the core mixing function of ChaCha20.
   *
   * a += b; d = rotl16(d ⊕ a); c += d; b = rotl12(b ⊕ c); a += b; d = rotl8(d ⊕ a); c += b; b =
   * rotl7(b ⊕ c)
   *
   * All additions are mod 2^32 (Int wrapping in Kotlin).
   */
  private fun quarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
    state[a] += state[b]
    state[d] = (state[d] xor state[a]).rotateLeft(16)
    state[c] += state[d]
    state[b] = (state[b] xor state[c]).rotateLeft(12)
    state[a] += state[b]
    state[d] = (state[d] xor state[a]).rotateLeft(8)
    state[c] += state[d]
    state[b] = (state[b] xor state[c]).rotateLeft(7)
  }

  /**
   * 10 double rounds: 4 column rounds then 4 diagonal rounds, repeated 10 times (RFC 8439 §2.2).
   * Column and diagonal quarter rounds operate on the same state array in-place; the order matches
   * the reference implementation.
   */
  private fun shuffleState(state: IntArray) {
    repeat(10) {
      // Column rounds
      quarterRound(state, 0, 4, 8, 12)
      quarterRound(state, 1, 5, 9, 13)
      quarterRound(state, 2, 6, 10, 14)
      quarterRound(state, 3, 7, 11, 15)
      // Diagonal rounds
      quarterRound(state, 0, 5, 10, 15)
      quarterRound(state, 1, 6, 11, 12)
      quarterRound(state, 2, 7, 8, 13)
      quarterRound(state, 3, 4, 9, 14)
    }
  }
}

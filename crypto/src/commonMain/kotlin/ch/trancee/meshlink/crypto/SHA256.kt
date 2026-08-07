package ch.trancee.meshlink.crypto

/**
 * SHA-256 round constants K0..K63 (RFC 6234 §5.1).
 *
 * First 32 bits of the fractional parts of the cube roots of the first 64 prime numbers. Stored as
 * `Long` literals then narrowed to `Int` so the high-bit-set values survive two's-complement
 * representation without ambiguity.
 */
private val sha256K =
    longArrayOf(
            0x428a2f98L,
            0x71374491L,
            0xb5c0fbcfL,
            0xe9b5dba5L,
            0x3956c25bL,
            0x59f111f1L,
            0x923f82a4L,
            0xab1c5ed5L,
            0xd807aa98L,
            0x12835b01L,
            0x243185beL,
            0x550c7dc3L,
            0x72be5d74L,
            0x80deb1feL,
            0x9bdc06a7L,
            0xc19bf174L,
            0xe49b69c1L,
            0xefbe4786L,
            0x0fc19dc6L,
            0x240ca1ccL,
            0x2de92c6fL,
            0x4a7484aaL,
            0x5cb0a9dcL,
            0x76f988daL,
            0x983e5152L,
            0xa831c66dL,
            0xb00327c8L,
            0xbf597fc7L,
            0xc6e00bf3L,
            0xd5a79147L,
            0x06ca6351L,
            0x14292967L,
            0x27b70a85L,
            0x2e1b2138L,
            0x4d2c6dfcL,
            0x53380d13L,
            0x650a7354L,
            0x766a0abbL,
            0x81c2c92eL,
            0x92722c85L,
            0xa2bfe8a1L,
            0xa81a664bL,
            0xc24b8b70L,
            0xc76c51a3L,
            0xd192e819L,
            0xd6990624L,
            0xf40e3585L,
            0x106aa070L,
            0x19a4c116L,
            0x1e376c08L,
            0x2748774cL,
            0x34b0bcb5L,
            0x391c0cb3L,
            0x4ed8aa4aL,
            0x5b9cca4fL,
            0x682e6ff3L,
            0x748f82eeL,
            0x78a5636fL,
            0x84c87814L,
            0x8cc70208L,
            0x90befffaL,
            0xa4506cebL,
            0xbef9a3f7L,
            0xc67178f2L,
        )
        .map { it.toInt() }
        .toIntArray()

/**
 * SHA-256 initial hash value H(0) (RFC 6234 §6.1).
 *
 * First 32 bits of the fractional parts of the square roots of the first eight prime numbers.
 */
private val sha256H0 =
    longArrayOf(
            0x6a09e667L,
            0xbb67ae85L,
            0x3c6ef372L,
            0xa54ff53aL,
            0x510e527fL,
            0x9b05688cL,
            0x1f83d9abL,
            0x5be0cd19L,
        )
        .map { it.toInt() }
        .toIntArray()

/**
 * SHA-256 message-digest function (RFC 6234 §5.1, §6).
 *
 * Pure-Kotlin, constant-time SHA-256 over 32-bit word arithmetic — no `BigInteger`, no
 * `java.security`/`javax`/`BouncyCastle`. All 32-bit words are Kotlin `Int` (signed); arithmetic
 * wraps modulo 2^32 via two's-complement overflow, `ushr` provides logical right shift (SHR), and
 * `rotateRight` provides circular right shift (ROTR).
 *
 * The compression function uses a fixed 64-round schedule with no data-dependent branching or
 * indexing, so execution time is independent of message content (ADR-0001, ADR-0003). The `@Secret`
 * annotation on [digest] lets the `:crypto-detekt-rules` `ConstantTimeRule` statically reject any
 * data-dependent `[if]`/`[when]` or secret-indexed array access in this file.
 */
public object SHA256 {

  /**
   * Computes the SHA-256 digest of [message].
   *
   * @param message the (possibly secret) bytes to hash.
   * @return 32-byte digest.
   */
  public fun digest(@Secret message: ByteArray): ByteArray {
    val hasher = SHA256Hasher()
    hasher.update(message, 0, message.size)
    return hasher.digest()
  }
}

/**
 * Incremental SHA-256 hasher (RFC 6234 §6.2) for internal composition by HMAC / HKDF. Holds mutable
 * state across [update] calls and finalises via [digest].
 *
 * Constant-time discipline is inherited from the public API's `@Secret` annotation: no
 * data-dependent branch or indexing touches secret material (ADR-0003).
 */
internal class SHA256Hasher {

  /** Eight 32-bit chaining variables H0..H7, initialised to §6.1 constants. */
  private val state = sha256H0.copyOf()

  /** Leftover bytes from the previous block — buffered until a full 64-byte block is available. */
  private val buffer = ByteArray(64)

  private var bufferLen = 0

  /** Total message length in bits, across all [update] calls. */
  private var totalBits = 0L

  /**
   * Feeds [length] bytes of [data] starting at [offset] into the hash.
   *
   * Data is accumulated in a 64-byte block buffer; whenever a full block is ready it is compressed
   * immediately. Remaining bytes stay buffered for the next call or the final [digest].
   */
  fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
    var pos = offset
    var remaining = length
    totalBits += length.toLong() shl 3
    while (remaining > 0) {
      val toCopy = minOf(remaining, 64 - bufferLen)
      data.copyInto(buffer, bufferLen, pos, pos + toCopy)
      bufferLen += toCopy
      pos += toCopy
      remaining -= toCopy
      if (bufferLen == 64) {
        processBlock(buffer, 0)
        bufferLen = 0
      }
    }
  }

  /**
   * Finalises the hash: pads the buffered data per RFC 6234 §4.1, processes the trailing block(s),
   * and returns the 32-byte big-endian digest.
   *
   * The hasher must not be used after this call.
   */
  fun digest(): ByteArray {
    // --- Step 1: append 0x80 (the "1" bit) ---------------------------
    buffer[bufferLen] = 0x80.toByte()

    // --- Step 2: zero-pad to position 56 (or process current block) ----
    // If 56..63 bytes are already buffered, the 0x80 + zero padding +
    // 8-byte length won't fit in the current block; process it first.
    if (bufferLen >= 56) {
      for (i in (bufferLen + 1) until 64) buffer[i] = 0
      processBlock(buffer, 0)
      for (i in 0 until 56) buffer[i] = 0
    } else {
      for (i in (bufferLen + 1) until 56) buffer[i] = 0
    }

    // --- Step 3: append 64-bit big-endian message bit-length -----------
    val bits = totalBits
    for (i in 0 until 8) {
      buffer[56 + i] = (bits ushr (56 - i * 8)).toByte()
    }

    processBlock(buffer, 0)

    // --- Step 4: serialise the 8 state words, big-endian ---------------
    val result = ByteArray(32)
    for (word in 0 until 8) {
      for (byte in 0 until 4) {
        result[word * 4 + byte] = (state[word] ushr (24 - byte * 8)).toByte()
      }
    }
    return result
  }

  // ------------------------------------------------------------------
  // §5.1 — logical functions (all constant-time, bitwise-only)
  // ------------------------------------------------------------------

  private fun processBlock(block: ByteArray, offset: Int) {
    // §6.2.1 — message schedule W[0..63]
    val w = IntArray(64)
    for (i in 0 until 16) {
      val j = offset + i * 4
      w[i] =
          (block[j].toInt() and 0xFF shl 24) or
              (block[j + 1].toInt() and 0xFF shl 16) or
              (block[j + 2].toInt() and 0xFF shl 8) or
              (block[j + 3].toInt() and 0xFF)
    }
    for (i in 16 until 64) {
      val s0 = sig0(w[i - 15])
      val s1 = sig1(w[i - 2])
      w[i] = s0 + w[i - 7] + s1 + w[i - 16]
    }

    // §6.2.2 — 64 compression rounds
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    for (t in 0 until 64) {
      val t1 = h + bsig1(e) + ch(e, f, g) + sha256K[t] + w[t]
      val t2 = bsig0(a) + maj(a, b, c)
      h = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
    }

    // §6.2.3 — accumulate into state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h
  }

  private fun ch(x: Int, y: Int, z: Int): Int = (x and y) xor (x.inv() and z)

  private fun maj(x: Int, y: Int, z: Int): Int = (x and y) xor (x and z) xor (y and z)

  private fun bsig0(x: Int): Int = x.rotateRight(2) xor x.rotateRight(13) xor x.rotateRight(22)

  private fun bsig1(x: Int): Int = x.rotateRight(6) xor x.rotateRight(11) xor x.rotateRight(25)

  private fun sig0(x: Int): Int = x.rotateRight(7) xor x.rotateRight(18) xor (x ushr 3)

  private fun sig1(x: Int): Int = x.rotateRight(17) xor x.rotateRight(19) xor (x ushr 10)
}

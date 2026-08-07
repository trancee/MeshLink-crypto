package ch.trancee.meshlink.crypto

/**
 * Combines a high 32-bit half [hi] and a low 32-bit half [lo] into a 64-bit Long.
 *
 * Kotlin disallows hex Long literals whose unsigned value exceeds [Long.MAX_VALUE] (high bit set),
 * so each SHA-512 constant is assembled from two 32-bit hex halves whose unsigned range fits.
 */
private fun L(hi: Long, lo: Long): Long = (hi shl 32) or (lo and 0xFFFFFFFFL)

/**
 * SHA-512 round constants K0..K79 (RFC 6234 §5.2).
 *
 * First 64 bits of the fractional parts of the cube roots of the first eighty prime numbers.
 */
private val sha512K =
    longArrayOf(
        L(0x428a2f98L, 0xd728ae22L),
        L(0x71374491L, 0x23ef65cdL),
        L(0xb5c0fbcfL, 0xec4d3b2fL),
        L(0xe9b5dba5L, 0x8189dbbcL),
        L(0x3956c25bL, 0xf348b538L),
        L(0x59f111f1L, 0xb605d019L),
        L(0x923f82a4L, 0xaf194f9bL),
        L(0xab1c5ed5L, 0xda6d8118L),
        L(0xd807aa98L, 0xa3030242L),
        L(0x12835b01L, 0x45706fbeL),
        L(0x243185beL, 0x4ee4b28cL),
        L(0x550c7dc3L, 0xd5ffb4e2L),
        L(0x72be5d74L, 0xf27b896fL),
        L(0x80deb1feL, 0x3b1696b1L),
        L(0x9bdc06a7L, 0x25c71235L),
        L(0xc19bf174L, 0xcf692694L),
        L(0xe49b69c1L, 0x9ef14ad2L),
        L(0xefbe4786L, 0x384f25e3L),
        L(0x0fc19dc6L, 0x8b8cd5b5L),
        L(0x240ca1ccL, 0x77ac9c65L),
        L(0x2de92c6fL, 0x592b0275L),
        L(0x4a7484aaL, 0x6ea6e483L),
        L(0x5cb0a9dcL, 0xbd41fbd4L),
        L(0x76f988daL, 0x831153b5L),
        L(0x983e5152L, 0xee66dfabL),
        L(0xa831c66dL, 0x2db43210L),
        L(0xb00327c8L, 0x98fb213fL),
        L(0xbf597fc7L, 0xbeef0ee4L),
        L(0xc6e00bf3L, 0x3da88fc2L),
        L(0xd5a79147L, 0x930aa725L),
        L(0x06ca6351L, 0xe003826fL),
        L(0x14292967L, 0x0a0e6e70L),
        L(0x27b70a85L, 0x46d22ffcL),
        L(0x2e1b2138L, 0x5c26c926L),
        L(0x4d2c6dfcL, 0x5ac42aedL),
        L(0x53380d13L, 0x9d95b3dfL),
        L(0x650a7354L, 0x8baf63deL),
        L(0x766a0abbL, 0x3c77b2a8L),
        L(0x81c2c92eL, 0x47edaee6L),
        L(0x92722c85L, 0x1482353bL),
        L(0xa2bfe8a1L, 0x4cf10364L),
        L(0xa81a664bL, 0xbc423001L),
        L(0xc24b8b70L, 0xd0f89791L),
        L(0xc76c51a3L, 0x0654be30L),
        L(0xd192e819L, 0xd6ef5218L),
        L(0xd6990624L, 0x5565a910L),
        L(0xf40e3585L, 0x5771202aL),
        L(0x106aa070L, 0x32bbd1b8L),
        L(0x19a4c116L, 0xb8d2d0c8L),
        L(0x1e376c08L, 0x5141ab53L),
        L(0x2748774cL, 0xdf8eeb99L),
        L(0x34b0bcb5L, 0xe19b48a8L),
        L(0x391c0cb3L, 0xc5c95a63L),
        L(0x4ed8aa4aL, 0xe3418acbL),
        L(0x5b9cca4fL, 0x7763e373L),
        L(0x682e6ff3L, 0xd6b2b8a3L),
        L(0x748f82eeL, 0x5defb2fcL),
        L(0x78a5636fL, 0x43172f60L),
        L(0x84c87814L, 0xa1f0ab72L),
        L(0x8cc70208L, 0x1a6439ecL),
        L(0x90befffaL, 0x23631e28L),
        L(0xa4506cebL, 0xde82bde9L),
        L(0xbef9a3f7L, 0xb2c67915L),
        L(0xc67178f2L, 0xe372532bL),
        L(0xca273eceL, 0xea26619cL),
        L(0xd186b8c7L, 0x21c0c207L),
        L(0xeada7dd6L, 0xcde0eb1eL),
        L(0xf57d4f7fL, 0xee6ed178L),
        L(0x06f067aaL, 0x72176fbaL),
        L(0x0a637dc5L, 0xa2c898a6L),
        L(0x113f9804L, 0xbef90daeL),
        L(0x1b710b35L, 0x131c471bL),
        L(0x28db77f5L, 0x23047d84L),
        L(0x32caab7bL, 0x40c72493L),
        L(0x3c9ebe0aL, 0x15c9bebcL),
        L(0x431d67c4L, 0x9c100d4cL),
        L(0x4cc5d4beL, 0xcb3e42b6L),
        L(0x597f299cL, 0xfc657e2aL),
        L(0x5fcb6fabL, 0x3ad6faecL),
        L(0x6c44198cL, 0x4a475817L),
    )

/**
 * SHA-512 initial hash value H(0) (RFC 6234 §6.3).
 *
 * First 64 bits of the fractional parts of the square roots of the first eight prime numbers.
 */
private val sha512H0 =
    longArrayOf(
        L(0x6a09e667L, 0xf3bcc908L),
        L(0xbb67ae85L, 0x84caa73bL),
        L(0x3c6ef372L, 0xfe94f82bL),
        L(0xa54ff53aL, 0x5f1d36f1L),
        L(0x510e527fL, 0xade682d1L),
        L(0x9b05688cL, 0x2b3e6c1fL),
        L(0x1f83d9abL, 0xfb41bd6bL),
        L(0x5be0cd19L, 0x137e2179L),
    )

/**
 * SHA-512 message-digest function (RFC 6234 §5.2, §6.3, §6.4).
 *
 * Internal — not exposed in the public API; consumed by EdDSA (ticket 09). Pure-Kotlin,
 * constant-time SHA-512 over 64-bit word arithmetic — no `BigInteger`, no
 * `java.security`/`javax`/`BouncyCastle`. All 64-bit words are Kotlin `Long` (signed); arithmetic
 * wraps modulo 2^64 via two's-complement overflow, `ushr` provides logical right shift (SHR), and
 * `rotateRight` provides circular right shift (ROTR).
 *
 * The compression function uses a fixed 80-round schedule with no data-dependent branching or
 * indexing, so execution time is independent of message content (ADR-0001, ADR-0003). The `@Secret`
 * annotation on [digest] lets the `:crypto-detekt-rules` `ConstantTimeRule` statically reject any
 * data-dependent `[if]`/`[when]` or secret-indexed array access in this file.
 */
internal object SHA512 {

  /**
   * Computes the SHA-512 digest of [message].
   *
   * @param message the (possibly secret) bytes to hash.
   * @return 64-byte digest.
   */
  fun digest(@Secret message: ByteArray): ByteArray {
    val hasher = SHA512Hasher()
    hasher.update(message, 0, message.size)
    return hasher.digest()
  }
}

/**
 * Incremental SHA-512 hasher (RFC 6234 §6.4) for internal composition. Holds mutable state across
 * [update] calls and finalises via [digest].
 *
 * Constant-time discipline is inherited from the public API's `@Secret` annotation: no
 * data-dependent branch or indexing touches secret material (ADR-0003).
 */
internal class SHA512Hasher {

  /** Eight 64-bit chaining variables H0..H7, initialised to §6.3 constants. */
  private val state = sha512H0.copyOf()

  /** Leftover bytes from the previous block — buffered until a full 128-byte block is available. */
  private val buffer = ByteArray(128)

  private var bufferLen = 0

  /** Total message length in bits, across all [update] calls. */
  private var totalBits = 0L

  /**
   * Feeds [length] bytes of [data] starting at [offset] into the hash.
   *
   * Data is accumulated in a 128-byte block buffer; whenever a full block is ready it is compressed
   * immediately. Remaining bytes stay buffered for the next call or the final [digest].
   */
  fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
    var pos = offset
    var remaining = length
    totalBits += length.toLong() shl 3
    while (remaining > 0) {
      val toCopy = minOf(remaining, 128 - bufferLen)
      data.copyInto(buffer, bufferLen, pos, pos + toCopy)
      bufferLen += toCopy
      pos += toCopy
      remaining -= toCopy
      if (bufferLen == 128) {
        processBlock(buffer, 0)
        bufferLen = 0
      }
    }
  }

  /**
   * Finalises the hash: pads the buffered data per RFC 6234 §4.2, processes the trailing block(s),
   * and returns the 64-byte big-endian digest.
   *
   * The hasher must not be used after this call.
   */
  fun digest(): ByteArray {
    // --- Step 1: append 0x80 (the "1" bit) ---------------------------
    buffer[bufferLen] = 0x80.toByte()

    // --- Step 2: zero-pad to position 112 (or process current block) ----
    // If 112..127 bytes are already buffered, the 0x80 + zero padding +
    // 16-byte length won't fit in the current block; process it first.
    if (bufferLen >= 112) {
      for (i in (bufferLen + 1) until 128) buffer[i] = 0
      processBlock(buffer, 0)
      for (i in 0 until 112) buffer[i] = 0
    } else {
      for (i in (bufferLen + 1) until 112) buffer[i] = 0
    }

    // --- Step 3: append 128-bit big-endian message bit-length -----------
    // High 64 bits are always zero for messages < 2^63 bits.
    for (i in 0 until 8) {
      buffer[112 + i] = 0
    }
    val bits = totalBits
    for (i in 0 until 8) {
      buffer[120 + i] = (bits ushr (56 - i * 8)).toByte()
    }

    processBlock(buffer, 0)

    // --- Step 4: serialise the 8 state words, big-endian ---------------
    val result = ByteArray(64)
    for (word in 0 until 8) {
      for (byte in 0 until 8) {
        result[word * 8 + byte] = (state[word] ushr (56 - byte * 8)).toByte()
      }
    }
    return result
  }

  // ------------------------------------------------------------------
  // §5.2 — logical functions (all constant-time, bitwise-only on Long)
  // ------------------------------------------------------------------

  private fun processBlock(block: ByteArray, offset: Int) {
    // §6.4.1 — message schedule W[0..79]
    val w = LongArray(80)
    for (i in 0 until 16) {
      val j = offset + i * 8
      w[i] =
          ((block[j].toLong() and 0xFFL) shl 56) or
              ((block[j + 1].toLong() and 0xFFL) shl 48) or
              ((block[j + 2].toLong() and 0xFFL) shl 40) or
              ((block[j + 3].toLong() and 0xFFL) shl 32) or
              ((block[j + 4].toLong() and 0xFFL) shl 24) or
              ((block[j + 5].toLong() and 0xFFL) shl 16) or
              ((block[j + 6].toLong() and 0xFFL) shl 8) or
              (block[j + 7].toLong() and 0xFFL)
    }
    for (i in 16 until 80) {
      val s0 = sig0(w[i - 15])
      val s1 = sig1(w[i - 2])
      w[i] = s0 + w[i - 7] + s1 + w[i - 16]
    }

    // §6.4.2 — 80 compression rounds
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    for (t in 0 until 80) {
      val t1 = h + bsig1(e) + ch(e, f, g) + sha512K[t] + w[t]
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

    // §6.4.3 — accumulate into state
    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h
  }

  private fun ch(x: Long, y: Long, z: Long): Long = (x and y) xor (x.inv() and z)

  private fun maj(x: Long, y: Long, z: Long): Long = (x and y) xor (x and z) xor (y and z)

  private fun bsig0(x: Long): Long = x.rotateRight(28) xor x.rotateRight(34) xor x.rotateRight(39)

  private fun bsig1(x: Long): Long = x.rotateRight(14) xor x.rotateRight(18) xor x.rotateRight(41)

  private fun sig0(x: Long): Long = x.rotateRight(1) xor x.rotateRight(8) xor (x ushr 7)

  private fun sig1(x: Long): Long = x.rotateRight(19) xor x.rotateRight(61) xor (x ushr 6)
}

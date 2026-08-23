package ch.trancee.meshlink.crypto

/*
 * Combines a high 32-bit half [hi] and a low 32-bit half [lo] into a 64-bit Long.
 *
 * Kotlin disallows hex Long literals whose unsigned value exceeds [Long.MAX_VALUE] (high bit set),
 * so each SHAKE256 round constant is assembled from two 32-bit hex halves whose unsigned range fits.
 */
private fun L(hi: Long, lo: Long): Long = (hi shl 32) or (lo and 0xFFFFFFFFL)

/**
 * Keccak-f[1600] round constants (24 values, one per round).
 *
 * Each is a 64-bit lane XORed into position [0,0] during the iota (ι) step. Constants with the high
 * bit set use [L] to bypass Kotlin's signed-Long hex literal restriction. Values match CPython's
 * HACL* and pycryptodome implementations (rc[9]=0x88, rc[16]=0x80000000_00008002,
 * rc[23]=0x80000000_80008008), verified against hashlib.sha3_256 known-answer tests.
 */
private val KeccakRoundConstants =
    longArrayOf(
        L(0x00000000L, 0x00000001L),
        L(0x00000000L, 0x00008082L),
        L(0x80000000L, 0x0000808aL),
        L(0x80000000L, 0x80008000L),
        L(0x00000000L, 0x0000808bL),
        L(0x00000000L, 0x80000001L),
        L(0x80000000L, 0x80008081L),
        L(0x80000000L, 0x00008009L),
        L(0x00000000L, 0x0000008aL),
        L(0x00000000L, 0x00000088L),
        L(0x00000000L, 0x80008009L),
        L(0x00000000L, 0x8000000aL),
        L(0x00000000L, 0x8000808bL),
        L(0x80000000L, 0x0000008bL),
        L(0x80000000L, 0x00008089L),
        L(0x80000000L, 0x00008003L),
        L(0x80000000L, 0x00008002L),
        L(0x80000000L, 0x00000080L),
        L(0x00000000L, 0x0000800aL),
        L(0x80000000L, 0x8000000aL),
        L(0x80000000L, 0x80008081L),
        L(0x80000000L, 0x00008080L),
        L(0x00000000L, 0x80000001L),
        L(0x80000000L, 0x80008008L),
    )

/**
 * Keccak-f[1600] ρ rotation offsets.
 *
 * Indexed as [x][y] (first index = x-coordinate, second index = y-coordinate), so lane (x, y) is
 * rotated left by [RotationConstants[x][y]] bits before being placed into its new position by π.
 *
 * Values verified against CPython's hashlib, pycryptodome, and HACL* Keccak implementations
 * (rc[2,3]=15, rc[2,4]=61, rc[3,2]=25, rc[3,4]=56, rc[4,3]=8, rc[4,4]=14). The
 * in3rsha/keccak-reference repo constants for these positions are incorrect.
 */
private val RotationConstants =
    arrayOf(
        intArrayOf(0, 36, 3, 41, 18), // x=0: r[0][y] for y=0..4
        intArrayOf(1, 44, 10, 45, 2), // x=1
        intArrayOf(62, 6, 43, 15, 61), // x=2 (r[2][3]=15, r[2][4]=61)
        intArrayOf(28, 55, 25, 21, 56), // x=3 (r[3][2]=25, r[3][4]=56)
        intArrayOf(27, 20, 39, 8, 14), // x=4 (r[4][3]=8, r[4][4]=14)
    )

/**
 * Rotates [v] left by [n] bits using `(v shl n) or (v ushr (64 - n))`.
 *
 * For n = 0, the shift amounts are 0 and 64; Kotlin's shift semantics reduce the right operand
 * modulo 64 for Long, so `ushr(64)` ≡ `ushr(0)`, yielding [v] itself. No branch is needed.
 */
private fun rol64(v: Long, n: Int): Long = (v shl n) or (v ushr (64 - n))

/**
 * SHAKE256 extendable-output function (FIPS 202 §8.4).
 *
 * Pure-Kotlin Keccak-f[1600] engine: rate = 136 bytes (1088 bits), capacity = 64 bytes (512 bits),
 * domain separation suffix 0x1F, pad10*1 padding (0x80 in the last rate byte). All 64-bit lane
 * arithmetic uses Kotlin [Long]; XOR absorbs and extracts bytes in little-endian lane order.
 *
 * The permutation uses 24 fixed rounds with no data-dependent branching or indexing, so execution
 * time is independent of message content (ADR-0001, ADR-0003). The `@Secret` annotation on [digest]
 * lets the `:crypto-detekt-rules` `ConstantTimeRule` statically reject any data-dependent
 * `[if]`/`[when]` or secret-indexed array access in this file.
 *
 * No native SHAKE256 API exists on JDK 21 (JCA has no SHAKE in the supported provider set for this
 * library), Android API 21+, or iOS CommonCrypto / Security.framework — the pure-Kotlin path is the
 * only implementation (ADR-0001, ticket 34).
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
 * Constant-time discipline is inherited from the public API's `@Secret` annotation: no
 * data-dependent branch or indexing touches secret material (ADR-0003).
 */
internal class SHAKE256Hasher {

  /** 25 × 64-bit lanes (1600 bits), initialised to zero. */
  private val state = LongArray(25)

  /**
   * Leftover bytes from the previous block — buffered until a full 136-byte rate block is
   * available.
   */
  private val buffer = ByteArray(136)

  private var bufferLen = 0

  /**
   * Feeds [length] bytes of [data] starting at [offset] into the sponge.
   *
   * Data is accumulated in a 136-byte block buffer; whenever a full rate block is ready it is XORed
   * into the state and Keccak-f[1600] is applied. Remaining bytes stay buffered for the next call
   * or the final [digest].
   */
  fun update(data: ByteArray, offset: Int = 0, length: Int = data.size - offset) {
    var pos = offset
    var remaining = length
    while (remaining > 0) {
      val toCopy = minOf(remaining, 136 - bufferLen)
      data.copyInto(buffer, bufferLen, pos, pos + toCopy)
      bufferLen += toCopy
      pos += toCopy
      remaining -= toCopy
      if (bufferLen == 136) {
        absorbBlock(buffer)
        bufferLen = 0
      }
    }
  }

  /**
   * Finalises the sponge: appends the SHAKE256 domain-suffix byte (0x1F) and pad10*1 (0x80 at the
   * last rate byte), absorbs the padded block, then squeezes [outputLength] bytes.
   *
   * The hasher must not be used after this call.
   */
  fun digest(outputLength: Int): ByteArray {
    // --- Step 1: zero stale data beyond the buffered message --------------
    for (i in bufferLen until 136) buffer[i] = 0

    // --- Step 2: domain-separation suffix 0x1F + pad10*1 (0x80) -----------
    buffer[bufferLen] = 0x1F.toByte()
    buffer[135] = (buffer[135].toInt() xor 0x80).toByte()

    // --- Step 3: absorb the padded block -----------------------------------
    absorbBlock(buffer)

    // --- Step 4: squeeze output (multi-block if needed) --------------------
    val result = ByteArray(outputLength)
    var produced = 0
    while (produced < outputLength) {
      val chunk = minOf(outputLength - produced, 136)
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

  // Absorb: XOR rate bytes into state lanes and permute

  /**
   * XORs [block] (136 bytes / 17 lanes) into the rate portion of the state and applies the full
   * permutation.
   */
  private fun absorbBlock(block: ByteArray) {
    for (lane in 0 until 17) {
      val base = lane * 8
      var value = 0L
      for (byte in 0 until 8) {
        value = value or ((block[base + byte].toLong() and 0xFFL) shl (byte * 8))
      }
      state[lane] = state[lane] xor value
    }
    keccakF1600(state)
  }

  private fun keccakF1600(state: LongArray) {
    for (round in 0 until 24) {
      theta(state)
      rhoPi(state)
      chi(state)
      iota(state, round)
    }
  }

  // θ — column parity diffusion
  private fun theta(state: LongArray) {
    val c = LongArray(5)
    for (x in 0..4) {
      c[x] = state[x] xor state[x + 5] xor state[x + 10] xor state[x + 15] xor state[x + 20]
    }
    val d = LongArray(5)
    for (x in 0..4) {
      d[x] = c[(x + 4) % 5] xor rol64(c[(x + 1) % 5], 1)
    }
    for (x in 0..4) {
      for (y in 0..4) {
        state[x + 5 * y] = state[x + 5 * y] xor d[x]
      }
    }
  }

  // ρ + π (combined) — bit-rotation + lane permutation
  // Forward π: B[y, (2x+3y)%5] = ROL(A[x,y], r[x][y]). Inverse: for target (x,y),
  // source lane = A[oldX, x] where oldX = (3y + x) % 5, rotated by r[oldX][x].
  // Since RotationConstants is indexed [x][y] = r[x][y], the lookup is
  // RotationConstants[oldX][x].
  private fun rhoPi(state: LongArray) {
    val newState = LongArray(25)
    for (x in 0..4) {
      for (y in 0..4) {
        val oldX = (3 * y + x) % 5
        newState[x + 5 * y] = rol64(state[oldX + 5 * x], RotationConstants[oldX][x])
      }
    }
    for (i in 0..24) state[i] = newState[i]
  }

  // χ — non-linear layer
  private fun chi(state: LongArray) {
    for (y in 0..4) {
      val base = 5 * y
      val row = LongArray(5)
      for (x in 0..4) row[x] = state[base + x]
      for (x in 0..4) {
        state[base + x] = row[x] xor (row[(x + 1) % 5].inv() and row[(x + 2) % 5])
      }
    }
  }

  // ι — round-constant injection into lane (0, 0)
  private fun iota(state: LongArray, round: Int) {
    state[0] = state[0] xor KeccakRoundConstants[round]
  }
}

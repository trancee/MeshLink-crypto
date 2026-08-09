/*
 * Poly1305 one-time MAC (RFC 8439 §2.5, §2.6).
 *
 * Pure-Kotlin implementation using 5 × 26-bit limbs (each stored in a 64-bit Long
 * for carry headroom), following the reduction strategy from RFC 7539 / floodyberry.
 * The key is clamped so that r < 2^130 with the high bits cleared, ensuring the
 * multiplication never overflows 64 bits per limb.
 *
 * No BigInteger, no platform crypto. All arithmetic is branchless: the final
 * h < p vs h ≥ p selection uses a bitmask derived from the sign bit, not an `if`.
 *
 * This file has no `@Secret` parameters — the Poly1305 key is derived from the
 * ChaCha20 keystream block 0 (ADR-0005 internal nonce), so there is no
 * file-scoped secret-name set to trip the `ConstantTimeRule`.
 */
package ch.trancee.meshlink.crypto

/** Poly1305 one-time MAC over mod 2^130−5 (RFC 8439 §2.5). */
internal object Poly1305 {

  /** Tag size in bytes (16 = 128 bits). */
  internal const val TAG_SIZE: Int = 16

  /** Key size in bytes (32 = 256 bits, the one-time pad for the final add). */
  private const val KEY_SIZE: Int = 32

  private const val BLOCK_SIZE: Int = 16

  // ------------------------------------------------------------------
  // LE byte / 26-bit limb helpers
  // ------------------------------------------------------------------

  /** Loads 4 bytes as a 32-bit LE value and extracts 26 bits at [shift]. */
  private fun load26(bytes: ByteArray, idx: Int, shift: Int): Long {
    val v = ChaCha20.load32LE(bytes, idx).toLong() and 0xFFFFFFFFL
    return (v ushr shift) and 0x3FFFFFF
  }

  // ------------------------------------------------------------------
  // MAC computation (RFC 8439 §2.5.2–§2.6)
  // ------------------------------------------------------------------

  /**
   * Computes the 16-byte Poly1305 MAC tag for [data] under 32-byte [key].
   *
   * @param key 32-byte one-time key (r || s clamping applied internally).
   * @param data message to authenticate.
   * @return 16-byte MAC tag.
   */
  internal fun mac(key: ByteArray, data: ByteArray): ByteArray {
    require(key.size == KEY_SIZE) { "poly1305 key must be $KEY_SIZE bytes" }

    var h0 = 0L
    var h1 = 0L
    var h2 = 0L
    var h3 = 0L
    var h4 = 0L
    var d0: Long
    var d1: Long
    var d2: Long
    var d3: Long
    var d4: Long
    var c: Long

    // Key clamping (RFC 7539 §2.5.2): r values are 26-bit limbs with high
    // bits cleared so that r < 2^130 (ensures per-block product fits in Long).
    val r0 = load26(key, 0, 0) and 0x3FFFFFF
    val r1 = load26(key, 3, 2) and 0x3FFFF03
    val r2 = load26(key, 6, 4) and 0x3FFC0FF
    val r3 = load26(key, 9, 6) and 0x3F03FFF
    val r4 = load26(key, 12, 8) and 0x00FFFFF

    val s1 = r1 * 5
    val s2 = r2 * 5
    val s3 = r3 * 5
    val s4 = r4 * 5

    // Buffer: 16 data bytes + 1 padding byte (for the Poly1305 1-bit pad).
    val buf = ByteArray(BLOCK_SIZE + 1)

    var i = 0
    while (i < data.size) {
      copyBlock(buf, data, i)
      h0 += load26(buf, 0, 0)
      h1 += load26(buf, 3, 2)
      h2 += load26(buf, 6, 4)
      h3 += load26(buf, 9, 6)
      h4 += load26(buf, 12, 8) or ((buf[BLOCK_SIZE].toLong() and 0xFF) shl 24)

      // d = r * h (polynomial multiplication in the RNS representation)
      d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1
      d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2
      d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3
      d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4
      d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0

      // Partial reduction mod 2^130-5: carry propagates through limbs.
      c = d0 ushr 26
      h0 = d0 and 0x3FFFFFF
      d1 += c
      c = d1 ushr 26
      h1 = d1 and 0x3FFFFFF
      d2 += c
      c = d2 ushr 26
      h2 = d2 and 0x3FFFFFF
      d3 += c
      c = d3 ushr 26
      h3 = d3 and 0x3FFFFFF
      d4 += c
      c = d4 ushr 26
      h4 = d4 and 0x3FFFFFF
      h0 += c * 5
      c = h0 ushr 26
      h0 = h0 and 0x3FFFFFF
      h1 += c

      i += BLOCK_SIZE
    }

    // Final reduction mod 2^130-5 (brings h0..h4 back to canonical form).
    c = h1 ushr 26
    h1 = h1 and 0x3FFFFFF
    h2 += c
    c = h2 ushr 26
    h2 = h2 and 0x3FFFFFF
    h3 += c
    c = h3 ushr 26
    h3 = h3 and 0x3FFFFFF
    h4 += c
    c = h4 ushr 26
    h4 = h4 and 0x3FFFFFF
    h0 += c * 5
    c = h0 ushr 26
    h0 = h0 and 0x3FFFFFF
    h1 += c

    // Compute h - p where p = 2^130 - 5 (g = h + 5 - 2^130).
    // If h >= p, g is non-negative → keep g (h - p).
    // If h <  p, g is negative  → keep h.
    val g0 = h0 + 5
    c = g0 ushr 26
    val g0r = g0 and 0x3FFFFFF
    var g1 = h1 + c
    c = g1 ushr 26
    val g1r = g1 and 0x3FFFFFF
    var g2 = h2 + c
    c = g2 ushr 26
    val g2r = g2 and 0x3FFFFFF
    var g3 = h3 + c
    c = g3 ushr 26
    val g3r = g3 and 0x3FFFFFF
    val g4 = h4 + c - (1L shl 26)

    // Branchless select: mask = 0 (h ≥ p, use g) or -1 (h < p, use h).
    // Kotlin's `Long.shr(n)` is arithmetic (sign-extending), matching Java's `>>`.
    val mask = g4 shr 63

    val fh0 = (h0 and mask) or (g0r and mask.inv())
    val fh1 = (h1 and mask) or (g1r and mask.inv())
    val fh2 = (h2 and mask) or (g2r and mask.inv())
    val fh3 = (h3 and mask) or (g3r and mask.inv())
    val fh4 = (h4 and mask) or (g4 and mask.inv())

    // h = h mod 2^128 (pack 5 × 26-bit limbs into 4 × 32-bit words)
    val w0 = (fh0 or (fh1 shl 26)) and 0xFFFFFFFFL
    val w1 = ((fh1 ushr 6) or (fh2 shl 20)) and 0xFFFFFFFFL
    val w2 = ((fh2 ushr 12) or (fh3 shl 14)) and 0xFFFFFFFFL
    val w3 = ((fh3 ushr 18) or (fh4 shl 8)) and 0xFFFFFFFFL

    // mac = (h + s) mod 2^128 (carry chain through 32-bit words)
    val pad0 = (ChaCha20.load32LE(key, 16).toLong() and 0xFFFFFFFFL)
    val pad1 = (ChaCha20.load32LE(key, 20).toLong() and 0xFFFFFFFFL)
    val pad2 = (ChaCha20.load32LE(key, 24).toLong() and 0xFFFFFFFFL)
    val pad3 = (ChaCha20.load32LE(key, 28).toLong() and 0xFFFFFFFFL)

    c = w0 + pad0
    val r0w = c and 0xFFFFFFFFL
    c = w1 + pad1 + (c ushr 32)
    val r1w = c and 0xFFFFFFFFL
    c = w2 + pad2 + (c ushr 32)
    val r2w = c and 0xFFFFFFFFL
    c = w3 + pad3 + (c ushr 32)
    val r3w = c and 0xFFFFFFFFL

    val mac = ByteArray(TAG_SIZE)
    ChaCha20.store32LE(mac, 0, r0w.toInt())
    ChaCha20.store32LE(mac, 4, r1w.toInt())
    ChaCha20.store32LE(mac, 8, r2w.toInt())
    ChaCha20.store32LE(mac, 12, r3w.toInt())
    return mac
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  /**
   * Copies up to 16 bytes from [data] at [offset] into [buf], then appends the Poly1305 padding bit
   * (1 followed by zeros) in `buf[16]`.
   *
   * For a full 16-byte block: `buf[0..15]` = data, `buf[16]` = 1. For a partial block:
   * `buf[0..n-1]` = data, `buf[n]` = 1, `buf[n+1..16]` = 0.
   */
  private fun copyBlock(buf: ByteArray, data: ByteArray, offset: Int) {
    val copyCount = minOf(BLOCK_SIZE, data.size - offset)
    for (j in 0 until copyCount) {
      buf[j] = data[offset + j]
    }
    buf[copyCount] = 1
    for (j in (copyCount + 1) until buf.size) {
      buf[j] = 0
    }
  }
}

/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-512 centered binomial noise sampling (FIPS 203 §6.2, ref/cbd.c).
 *
 * Pure-Kotlin implementation of the two CBD variants used by Kyber:
 * - [cbd2]: η = 2, reads 4 bytes per 8 coefficients (load32 + 2-bit extraction).
 * - [cbd3]: η = 3, reads 3 bytes per 4 coefficients (load24 + 3-bit extraction).
 *
 * The `load24`/`load32` helpers read bytes in little-endian order, matching the
 * C reference's `load24_littleendian` / `load32_littleendian`.
 *
 * Reference: pq-crystals/kyber ref/cbd.c
 */
package ch.trancee.meshlink.crypto

// ------------------------------------------------------------------
// Little-endian byte loaders (ref/cbd.c)
// ------------------------------------------------------------------

/** Load 4 bytes from [buf] at [offset] as a little-endian unsigned 32-bit integer. */
private fun load24LittleEndian(buf: ByteArray, offset: Int): Int {
  return (buf[offset].toInt() and 0xFF) or
      ((buf[offset + 1].toInt() and 0xFF) shl 8) or
      ((buf[offset + 2].toInt() and 0xFF) shl 16)
}

/** Load 4 bytes from [buf] at [offset] as a little-endian unsigned 32-bit integer. */
private fun load32LittleEndian(buf: ByteArray, offset: Int): Int {
  return (buf[offset].toInt() and 0xFF) or
      ((buf[offset + 1].toInt() and 0xFF) shl 8) or
      ((buf[offset + 2].toInt() and 0xFF) shl 16) or
      ((buf[offset + 3].toInt() and 0xFF) shl 24)
}

// ------------------------------------------------------------------
// CBD (ref/cbd.c)
// ------------------------------------------------------------------

/**
 * Centered binomial distribution with η = 2 (ref/cbd.c `cbd2`).
 *
 * Reads `2*KYBER_N/4 = 128` bytes from [buf], producing 256 coefficients each in [-2, 2]. Each
 * group of 4 bytes yields 8 coefficients via 2-bit extraction.
 *
 * @param r output coefficient array (256 elements, filled in place)
 * @param buf input uniformly-random bytes (128 bytes)
 */
internal fun cbd2(r: IntArray, buf: ByteArray) {
  for (i in 0 until MLKEM_N / 8) {
    val t = load32LittleEndian(buf, 4 * i)
    var d = t and 0x55555555
    d += (t ushr 1) and 0x55555555

    for (j in 0 until 8) {
      val a = (d ushr (4 * j)) and 0x3
      val b = (d ushr (4 * j + 2)) and 0x3
      r[8 * i + j] = a - b
    }
  }
}

/**
 * Centered binomial distribution with η = 3 (ref/cbd.c `cbd3`).
 *
 * Only used for ML-KEM-512 (η1 = 3). Reads `3*KYBER_N/4 = 192` bytes from [buf], producing 256
 * coefficients each in [-3, 3]. Each group of 3 bytes yields 4 coefficients via 3-bit extraction.
 *
 * @param r output coefficient array (256 elements, filled in place)
 * @param buf input uniformly-random bytes (192 bytes)
 */
internal fun cbd3(r: IntArray, buf: ByteArray) {
  for (i in 0 until MLKEM_N / 4) {
    val t = load24LittleEndian(buf, 3 * i)
    var d = t and 0x00249249
    d += (t ushr 1) and 0x00249249
    d += (t ushr 2) and 0x00249249

    for (j in 0 until 4) {
      val a = (d ushr (6 * j)) and 0x7
      val b = (d ushr (6 * j + 3)) and 0x7
      r[4 * i + j] = a - b
    }
  }
}

/**
 * Sample a polynomial with coefficients in [-η, η] using the appropriate CBD variant.
 *
 * For η1 = 3 (ML-KEM-512), calls [cbd3]; for η1 = 2, calls [cbd2]. The [buf] must contain exactly
 * `MLKEM_ETA1 * MLKEM_N / 4` bytes (192 for η1 = 3).
 *
 * @param r output coefficient array (256 elements)
 * @param buf PRF output bytes (192 bytes for η1 = 3, 128 bytes for η1 = 2)
 */
internal fun polyCbdEta1(r: IntArray, buf: ByteArray) {
  if (MLKEM_ETA1 == 3) cbd3(r, buf) else cbd2(r, buf)
}

/**
 * Sample a polynomial with coefficients in [-η2, η2] using `cbd2` (η2 = 2 for all ML-KEM parameter
 * sets).
 *
 * The [buf] must contain exactly `MLKEM_ETA2 * MLKEM_N / 4` = 128 bytes.
 *
 * @param r output coefficient array (256 elements)
 * @param buf PRF output bytes (128 bytes)
 */
internal fun polyCbdEta2(r: IntArray, buf: ByteArray) {
  cbd2(r, buf)
}

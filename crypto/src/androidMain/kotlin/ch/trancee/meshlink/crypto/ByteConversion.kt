/*
 * SPDX-License-Identifier: Apache-2.0
 * Android actual for platform-optimized little-endian byte-to-Long conversion (ADR-0001).
 *
 * Uses fully unrolled manual byte extraction — no ByteBuffer allocation.
 * Same approach as KotlinCrypto/bitops `unpackLELong`/`packLELong`.
 */
package ch.trancee.meshlink.crypto

@PublishedApi
internal actual fun leBytesToLong(data: ByteArray, offset: Int): Long =
    ((data[offset].toLong() and 0xFFL) or
        ((data[offset + 1].toLong() and 0xFFL) shl 8) or
        ((data[offset + 2].toLong() and 0xFFL) shl 16) or
        ((data[offset + 3].toLong() and 0xFFL) shl 24) or
        ((data[offset + 4].toLong() and 0xFFL) shl 32) or
        ((data[offset + 5].toLong() and 0xFFL) shl 40) or
        ((data[offset + 6].toLong() and 0xFFL) shl 48) or
        ((data[offset + 7].toLong() and 0xFFL) shl 56))

@PublishedApi
internal actual fun longToLEBytes(value: Long, data: ByteArray, offset: Int) {
  data[offset] = (value and 0xFFL).toByte()
  data[offset + 1] = (value ushr 8).toByte()
  data[offset + 2] = (value ushr 16).toByte()
  data[offset + 3] = (value ushr 24).toByte()
  data[offset + 4] = (value ushr 32).toByte()
  data[offset + 5] = (value ushr 40).toByte()
  data[offset + 6] = (value ushr 48).toByte()
  data[offset + 7] = (value ushr 56).toByte()
}

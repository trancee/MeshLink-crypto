/*
 * SPDX-License-Identifier: Apache-2.0
 * iOS actual for platform-optimized little-endian byte-to-Long conversion (ADR-0001).
 *
 * iOS Kotlin/Native lacks java.nio.ByteBuffer (JVM-only API). Uses a manual shl/or/and chain
 * for byte-level LE conversion. The constant-time nature of this conversion is not critical —
 * it is only applied to non-secret rate data (message bytes, padded blocks).
 */
package ch.trancee.meshlink.crypto

@PublishedApi
internal actual fun leBytesToLong(data: ByteArray, offset: Int): Long {
  var value = 0L
  for (byte in 0 until 8) {
    value = value or ((data[offset + byte].toLong() and 0xFFL) shl (byte * 8))
  }
  return value
}

@PublishedApi
internal actual fun longToLEBytes(value: Long, data: ByteArray, offset: Int) {
  for (byte in 0 until 8) {
    data[offset + byte] = (value ushr (byte * 8)).toByte()
  }
}

/*
 * SPDX-License-Identifier: Apache-2.0
 * Android actual for platform-optimized little-endian byte-to-Long conversion (ADR-0001).
 *
 * Uses java.nio.ByteBuffer.wrap to create a zero-copy view over the byte array, then reads/writes
 * a 64-bit long in little-endian order. No Unsafe reflection, no VarHandle. Android API 21+
 * supports ByteBuffer (via java.nio, available since API 1) and ByteOrder.LITTLE_ENDIAN.
 *
 * See: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/ByteBuffer.html
 */
package ch.trancee.meshlink.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder

private val LE: ByteOrder = ByteOrder.LITTLE_ENDIAN

@PublishedApi
internal actual fun leBytesToLong(data: ByteArray, offset: Int): Long =
    ByteBuffer.wrap(data, offset, Long.SIZE_BITS / Byte.SIZE_BITS).order(LE).getLong()

@PublishedApi
internal actual fun longToLEBytes(value: Long, data: ByteArray, offset: Int) {
  ByteBuffer.wrap(data, offset, Long.SIZE_BITS / Byte.SIZE_BITS).order(LE).putLong(value)
}

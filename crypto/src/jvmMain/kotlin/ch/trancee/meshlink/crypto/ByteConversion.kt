/*
 * SPDX-License-Identifier: Apache-2.0
 * JVM actual for platform-optimized little-endian byte-to-Long conversion (ADR-0001).
 *
 * Uses java.nio.ByteBuffer.wrap to create a zero-copy view over the byte array, then reads/writes
 * a 64-bit long in little-endian order. No data copy, no Unsafe reflection, no VarHandle.
 *
 * Rationale: ByteBuffer.wrap(data, offset, 8) creates a view buffer backed by the existing byte
 * array (no allocation of the underlying memory). The .order(ByteOrder.LITTLE_ENDIAN) call sets
 * the byte order in place (returns the same buffer object). The .getLong() / .putLong() call reads
 * or writes 8 bytes at the current position (which is `offset`) in the specified byte order.
 *
 * The JIT (C2 on JVM, ART on Android) optimizes ByteBuffer view operations on heap buffers to
 * direct array access with bounds checks eliminated, matching Unsafe.getLong performance for
 * this access pattern.
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

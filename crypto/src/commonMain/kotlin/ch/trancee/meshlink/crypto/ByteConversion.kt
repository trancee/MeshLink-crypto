/*
 * SPDX-License-Identifier: Apache-2.0
 * Platform-optimized little-endian byte-to-Long conversion (ADR-0001).
 *
 * platform-specific intrinsics: fully unrolled manual shl/or/and chains on all platforms (no ByteBuffer, no Unsafe, no VarHandle).
 */
package ch.trancee.meshlink.crypto

/**
 * Reads 8 little-endian bytes from [data] starting at [offset] as a 64-bit Long.
 *
 * Uses fully unrolled manual byte extraction on all platforms — no ByteBuffer allocation, no
 * Unsafe, no VarHandle. The JIT eliminates bounds checks in hot loops.
 */
internal expect inline fun leBytesToLong(data: ByteArray, offset: Int): Long

/** Writes [value] as 8 little-endian bytes into [data] starting at [offset]. */
internal expect inline fun longToLEBytes(value: Long, data: ByteArray, offset: Int)

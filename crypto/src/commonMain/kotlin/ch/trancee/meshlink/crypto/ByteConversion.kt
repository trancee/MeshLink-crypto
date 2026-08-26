/*
 * SPDX-License-Identifier: Apache-2.0
 * Platform-optimized little-endian byte-to-Long conversion (ADR-0001).
 *
 * platform-specific intrinsics: java.nio.ByteBuffer on JVM/Android, manual shl/or on iOS.
 */
package ch.trancee.meshlink.crypto

/**
 * Reads 8 little-endian bytes from [data] starting at [offset] as a 64-bit Long.
 *
 * On JVM/Android, uses java.nio.ByteBuffer for a zero-copy 8-byte little-endian read. On iOS, uses
 * a manual shl/or chain (no ByteBuffer available).
 */
internal expect fun leBytesToLong(data: ByteArray, offset: Int): Long

/** Writes [value] as 8 little-endian bytes into [data] starting at [offset]. */
internal expect fun longToLEBytes(value: Long, data: ByteArray, offset: Int)

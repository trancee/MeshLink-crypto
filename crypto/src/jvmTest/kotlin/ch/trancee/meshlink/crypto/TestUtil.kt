package ch.trancee.meshlink.crypto

/**
 * Decodes a hex string into a byte array for use in known-answer tests.
 *
 * Shared across all SHA-256 / SHA-512 test classes so KAT vectors are parsed from a single
 * implementation rather than duplicated per test file.
 */
internal fun hex(s: String): ByteArray {
    require(s.length % 2 == 0) { "hex string must have even length, got ${s.length} chars: ${s.take(8)}..." }
    return ByteArray(s.length / 2) { i ->
        val hi = s[i * 2].digitToInt(16)
        val lo = s[i * 2 + 1].digitToInt(16)
        (hi shl 4 or lo).toByte()
    }
}

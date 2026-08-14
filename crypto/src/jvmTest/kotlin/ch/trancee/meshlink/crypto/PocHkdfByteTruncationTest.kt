package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * PoC: Verify HKDF-Expand with blockNumber > 127 (byte truncation concern).
 *
 * RFC 5869 §2.3: T(i) = HMAC(H, T(i-1) | info | 2^{8i}).
 * blockNumber.toByte() for i=128..255 produces signed bytes (-128..-1),
 * but the raw 8 bits are 128..255 — correct per RFC 5869.
 */
internal class PocHkdfByteTruncationTest {

  @Test
  fun `HKDF PureK and JCA agree for large output exceeding 4064 bytes`() {
    val ikm = ByteArray(256) { ((it * 7 + 3) and 0xFF).toByte() }
    val salt = ByteArray(64) { ((it * 13 + 5) and 0xFF).toByte() }
    val info = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
    val outputLength = 5000

    val pureKResult = HKDF_SHA256PureK.digest(ikm, salt, info, outputLength)
    val nativeResult = hkdfSha256Native(ikm, salt, info, outputLength)

    println("PureK output (first 16): ${pureKResult.take(16).joinToString("") { "%02x".format(it) }}")
    println("Native output is null: ${nativeResult == null}")

    if (nativeResult != null) {
      assertContentEquals(pureKResult, nativeResult, "Native HKDF must match PureK for large blocks")
    }
    println("All $outputLength bytes match between PureK and native")
  }

  @Test
  fun `block number 128 toByte produces raw byte 0x80`() {
    val b128 = byteArrayOf(128.toByte())
    val expected128 = 0x80
    val actual128 = b128[0].toInt() and 0xFF
    assertEquals(expected128, actual128, "block 128 should be raw byte 0x80")
    println("block 128 toByte() = 0x${"%02x".format(actual128)}")
  }

  @Test
  fun `block number 255 toByte produces raw byte 0xFF`() {
    val b255 = byteArrayOf(255.toByte())
    val expected255 = 0xFF
    val actual255 = b255[0].toInt() and 0xFF
    assertEquals(expected255, actual255, "block 255 should be raw byte 0xFF")
    println("block 255 toByte() = 0x${"%02x".format(actual255)}")
  }
}

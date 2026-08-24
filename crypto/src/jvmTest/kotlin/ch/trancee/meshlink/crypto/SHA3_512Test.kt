/**
 * SHA3-512 known-answer tests (FIPS 202 §6.2).
 *
 * The primary vectors (empty, "abc", million-a's) are the official NIST CAVP KAT vectors from FIPS
 * 202 Appendix B.2, Table 6. The block-boundary vectors (71/72/73/144/145 bytes) and multi-block
 * input vectors are computed via Python's
 * [`hashlib.sha3_512`](https://docs.python.org/3/library/hashlib.html), a FIPS 202-compliant
 * reference implementation. Wycheproof has no SHA3-512 corpus, so inline known-answer vectors are
 * the correctness oracle per [ADR-0003](docs/adr/0003-verification-gates.md) §1 and
 * [docs/how-to/add-primitive.md](docs/how-to/add-primitive.md) §Step 7. Keccak-f[1600] round
 * constants cross-verified against [XKCP](https://github.com/XKCP/XKCP).
 *
 * Parameters: rate = 72 bytes (576 bits), capacity = 128 bytes (1024 bits), suffix = 0x06, output =
 * 64 bytes. SHA3-512 uses suffix 0x06 (2-bit domain separator "01") vs SHAKE's 0x1F; the pad10*1
 * termination is identical.
 *
 * Verified:
 * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 */
package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import org.junit.jupiter.api.Tag

internal class SHA3_512Test {

  private fun hex(s: String): ByteArray {
    val clean = s.replace(" ", "")
    require(clean.length % 2 == 0) { "hex string must have even length" }
    return ByteArray(clean.length / 2) { i ->
      val hi = clean[i * 2].digitToInt(16)
      val lo = clean[i * 2 + 1].digitToInt(16)
      (hi shl 4 or lo).toByte()
    }
  }

  // ------------------------------------------------------------------
  // FIPS 202 known-answer test vectors (NIST CAVP KATs + Python hashlib)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 empty message`() {
    assertContentEquals(
        hex(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a" +
                "615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        ),
        SHA3_512PureK.digest(ByteArray(0)),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 abc message`() {
    assertContentEquals(
        hex(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" +
                "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        ),
        SHA3_512PureK.digest("abc".encodeToByteArray()),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 one million a's`() {
    val input = ByteArray(1_000_000) { 0x61.toByte() }
    assertContentEquals(
        hex(
            "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859" +
                "ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87"
        ),
        SHA3_512PureK.digest(input),
    )
  }

  // ------------------------------------------------------------------
  // Block-boundary coverage (exercises every absorb + padding path)
  // SHA3-512 rate = 72 bytes; padding boundary = 71 (rate - 1 for 0x80)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 boundary 71 bytes - padding fits in the first rate block`() {
    assertContentEquals(
        hex(
            "070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3db5" +
                "35a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c"
        ),
        SHA3_512PureK.digest(ByteArray(71) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 boundary 72 bytes - exactly one full rate block`() {
    assertContentEquals(
        hex(
            "a8ae722a78e10cbbc413886c02eb5b369a03f6560084aff566bd597bb7ad8c1ccd" +
                "86e81296852359bf2faddb5153c0a7445722987875e74287adac21adebe952"
        ),
        SHA3_512PureK.digest(ByteArray(72) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 boundary 73 bytes - one byte into the second rate block`() {
    assertContentEquals(
        hex(
            "23e6a8815f8201dbbf6a5463be8dcadb1acea9df5f8998954e59ac9565cf6d29b" +
                "17aa27a5e8b0fc06343db6122d6e544d27583ddc78504d08203217e7e65b6bd"
        ),
        SHA3_512PureK.digest(ByteArray(73) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 boundary 144 bytes - exactly two full rate blocks`() {
    assertContentEquals(
        hex(
            "446cd4d7ba19510dcc776b21045bc68d424b5b840e14685e149bb238b5f473c03" +
                "56b69e04f0f5785eefce20ff09e678b080d8aac64568c5edf001cd32b2ed7a8"
        ),
        SHA3_512PureK.digest(ByteArray(144) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 boundary 145 bytes - one byte into the third rate block`() {
    assertContentEquals(
        hex(
            "84a7b171615f4f0024b772defd5ea21a536bb1e52306fa7ad412c532ac919f6b" +
                "645e412aa7f5d979808c8ae03ca7d159363dcdb179c9b03f908e3b3526cbf4de"
        ),
        SHA3_512PureK.digest(ByteArray(145) { 0x61 }),
    )
  }

  // ------------------------------------------------------------------
  // Incremental hasher tests (exercises SHA3_512Hasher buffering)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 incremental update matches one-shot digest`() {
    val data = ByteArray(200) { (it * 7).toByte() }
    val oneShot = SHA3_512PureK.digest(data)

    val hasher = SHA3_512Hasher()
    hasher.update(data, 0, 50)
    hasher.update(data, 50, 100)
    hasher.update(data, 150, 50)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 incremental update with defaults matches one-shot`() {
    val data = ByteArray(300) { (it * 13).toByte() }
    val oneShot = SHA3_512PureK.digest(data)

    val hasher = SHA3_512Hasher()
    hasher.update(data)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 digest over multi-update with exact-block boundaries`() {
    // 72 + 72 + 1 = 145 bytes: two full rate blocks + 1 byte buffered
    val a = ByteArray(72) { 0x61 }
    val b = ByteArray(72) { 0x62 }
    val c = byteArrayOf(0x63)
    val data = a + b + c
    val oneShot = SHA3_512PureK.digest(data)

    val hasher = SHA3_512Hasher()
    hasher.update(a, 0, a.size)
    hasher.update(b, 0, b.size)
    hasher.update(c, 0, c.size)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 digest over multi-update with byte-at-a-time feeding`() {
    // Feed one byte at a time — exercises maximal buffering paths.
    val data = ByteArray(300) { (it * 5).toByte() }
    val oneShot = SHA3_512PureK.digest(data)

    val hasher = SHA3_512Hasher()
    data.forEachIndexed { i, _ -> hasher.update(data, i, 1) }
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 hash over multi-block input with varied content`() {
    // 400 bytes of pseudo-random data crosses multiple rate block boundaries
    val data = ByteArray(400) { (it * 17 + 3).toByte() }
    val expected = java.security.MessageDigest.getInstance("SHA3-512").digest(data)
    assertContentEquals(expected, SHA3_512PureK.digest(data))
  }

  // ------------------------------------------------------------------
  // Error-state coverage
  // ------------------------------------------------------------------

  @Tag("security")
  @Test
  fun `SHA3-512 update after digest throws`() {
    val hasher = SHA3_512Hasher()
    hasher.update("test".toByteArray())
    hasher.digest()
    try {
      hasher.update("more".toByteArray())
      assert(false) { "update after digest should throw" }
    } catch (e: IllegalStateException) {
      // Expected
    }
  }

  @Tag("security")
  @Test
  fun `SHA3-512 digest twice throws`() {
    val hasher = SHA3_512Hasher()
    hasher.update("test".toByteArray())
    hasher.digest()
    try {
      hasher.digest()
      assert(false) { "digest twice should throw" }
    } catch (e: IllegalStateException) {
      // Expected
    }
  }

  // ------------------------------------------------------------------
  // Public API facade coverage
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 public API via Hasher matches PureK`() {
    val message = "abc".encodeToByteArray()
    val expected = SHA3_512PureK.digest(message)
    val actual = Hasher.sha3_512(message).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-512 public API via Crypto facade matches PureK`() {
    val message = "abc".encodeToByteArray()
    val expected = SHA3_512PureK.digest(message)
    val actual = Crypto.sha3_512(message).getOrThrow()
    assertContentEquals(expected, actual)
  }
}

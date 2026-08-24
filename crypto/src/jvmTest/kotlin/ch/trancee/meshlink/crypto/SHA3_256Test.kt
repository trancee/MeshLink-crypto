/**
 * SHA3-256 known-answer tests (FIPS 202 §6.1).
 *
 * The primary vectors (empty, "abc", million-a's) are the official NIST CAVP KAT vectors from FIPS
 * 202 Appendix B.1/B.2, Table 6. The block-boundary vectors (135/136/137/272/273 bytes) and
 * multi-block input vectors are computed via Python's
 * [`hashlib.sha3_256`](https://docs.python.org/3/library/hashlib.html), a FIPS 202-compliant
 * reference implementation that produces byte-identical output to the CAVP test suite. Wycheproof
 * has no SHA3-256 corpus, so inline known-answer vectors are the correctness oracle per
 * [ADR-0003](docs/adr/0003-verification-gates.md) §1 and
 * [docs/how-to/add-primitive.md](docs/how-to/add-primitive.md) §Step 7. Keccak-f[1600] round
 * constants cross-verified against [XKCP](https://github.com/XKCP/XKCP) and TweetableFIPS202.c.
 *
 * Parameters: rate = 136 bytes (1088 bits), capacity = 64 bytes (512 bits), suffix = 0x06, output =
 * 32 bytes. SHA3-256 uses suffix 0x06 (2-bit domain separator "01") vs SHAKE's 0x1F; the pad10*1
 * termination is identical.
 *
 * Verified:
 * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 */
package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import org.junit.jupiter.api.Tag

internal class SHA3_256Test {

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
  // FIPS 202 §D.4 SHA3-256 known-answer test vectors (NIST CAVP KATs + Python hashlib)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 empty message`() {
    assertContentEquals(
        hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        SHA3_256PureK.digest(ByteArray(0)),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 abc message`() {
    assertContentEquals(
        hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        SHA3_256PureK.digest("abc".encodeToByteArray()),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 one million a's`() {
    val input = ByteArray(1_000_000) { 0x61.toByte() }
    assertContentEquals(
        hex("5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
        SHA3_256PureK.digest(input),
    )
  }

  // ------------------------------------------------------------------
  // Block-boundary coverage (exercises every absorb + padding path)
  // SHA3-256 rate = 136 bytes; padding boundary = 135 (rate - 1 for 0x80)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 boundary 135 bytes - padding fits in the first rate block`() {
    assertContentEquals(
        hex("8094bb53c44cfb1e67b7c30447f9a1c33696d2463ecc1d9c92538913392843c9"),
        SHA3_256PureK.digest(ByteArray(135) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 boundary 136 bytes - exactly one full rate block`() {
    assertContentEquals(
        hex("3fc5559f14db8e453a0a3091edbd2bc25e11528d81c66fa570a4efdcc2695ee1"),
        SHA3_256PureK.digest(ByteArray(136) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 boundary 137 bytes - one byte into the second rate block`() {
    assertContentEquals(
        hex("f8d6846cedd2ccfadf15c5879ef95af724d799eed7391fb1c91f95344e738614"),
        SHA3_256PureK.digest(ByteArray(137) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 boundary 272 bytes - exactly two full rate blocks`() {
    assertContentEquals(
        hex("a490357b9b3fb39d0a89a117734e5b020b1f33c7bf3fa3575c396425432003d3"),
        SHA3_256PureK.digest(ByteArray(272) { 0x61 }),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 boundary 273 bytes - one byte into the third rate block`() {
    assertContentEquals(
        hex("7930a0e2cde6f949ea52204a2fde51856de566d96d2ebe896656450a2b10b445"),
        SHA3_256PureK.digest(ByteArray(273) { 0x61 }),
    )
  }

  // ------------------------------------------------------------------
  // Incremental hasher tests (exercises SHA3_256Hasher buffering)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 incremental update matches one-shot digest`() {
    val data = ByteArray(200) { (it * 7).toByte() }
    val oneShot = SHA3_256PureK.digest(data)

    val hasher = SHA3_256Hasher()
    hasher.update(data, 0, 50)
    hasher.update(data, 50, 100)
    hasher.update(data, 150, 50)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 incremental update with defaults matches one-shot`() {
    val data = ByteArray(300) { (it * 13).toByte() }
    val oneShot = SHA3_256PureK.digest(data)

    val hasher = SHA3_256Hasher()
    hasher.update(data)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 digest over multi-update with exact-block boundaries`() {
    // 136 + 136 + 1 = 273 bytes: two full rate blocks + 1 byte buffered
    val a = ByteArray(136) { 0x61 }
    val b = ByteArray(136) { 0x62 }
    val c = byteArrayOf(0x63)
    val data = a + b + c
    val oneShot = SHA3_256PureK.digest(data)

    val hasher = SHA3_256Hasher()
    hasher.update(a, 0, a.size)
    hasher.update(b, 0, b.size)
    hasher.update(c, 0, c.size)
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 digest over multi-update with byte-at-a-time feeding`() {
    // Feed one byte at a time — exercises maximal buffering paths.
    val data = ByteArray(300) { (it * 5).toByte() }
    val oneShot = SHA3_256PureK.digest(data)

    val hasher = SHA3_256Hasher()
    data.forEachIndexed { i, _ -> hasher.update(data, i, 1) }
    assertContentEquals(oneShot, hasher.digest())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 hash over multi-block input with varied content`() {
    // 400 bytes of pseudo-random data crosses two rate block boundaries
    val data = ByteArray(400) { (it * 17 + 3).toByte() }
    val expected = java.security.MessageDigest.getInstance("SHA3-256").digest(data)
    assertContentEquals(expected, SHA3_256PureK.digest(data))
  }

  // ------------------------------------------------------------------
  // Error-state coverage
  // ------------------------------------------------------------------

  @Tag("security")
  @Test
  fun `SHA3-256 update after digest throws`() {
    val hasher = SHA3_256Hasher()
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
  fun `SHA3-256 digest twice throws`() {
    val hasher = SHA3_256Hasher()
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
  fun `SHA3-256 public API via Hasher matches PureK`() {
    val message = "abc".encodeToByteArray()
    val expected = SHA3_256PureK.digest(message)
    val actual = Hasher.sha3_256(message).getOrThrow()
    assertContentEquals(expected, actual)
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHA3-256 public API via Crypto facade matches PureK`() {
    val message = "abc".encodeToByteArray()
    val expected = SHA3_256PureK.digest(message)
    val actual = Crypto.sha3_256(message).getOrThrow()
    assertContentEquals(expected, actual)
  }
}

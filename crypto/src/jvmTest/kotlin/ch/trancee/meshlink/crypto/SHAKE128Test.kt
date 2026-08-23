/**
 * SHAKE128 known-answer tests (FIPS 202 §8.3).
 *
 * The primary vectors (empty, "abc", 0x19, million-a's) are the official NIST CAVP KAT vectors from
 * FIPS 202 §D.4. The multi-block squeeze boundary vectors (168/169/200/336 bytes) and absorb
 * boundary vectors (167/168/169/336/337 bytes of 0x61) are computed via Python's
 * [`hashlib.shake_128`](https://docs.python.org/3/library/hashlib.html), a FIPS 202-compliant
 * reference implementation that produces byte-identical output to the CAVP test suite. Wycheproof
 * has no SHAKE corpus, so these inline known-answer vectors are the correctness oracle per
 * [ADR-0003](docs/adr/0003-verification-gates.md) §1 and
 * [docs/how-to/add-primitive.md](docs/how-to/add-primitive.md) §Step 7. Keccak-f[1600] round
 * constants verified against [XKCP](https://github.com/XKCP/XKCP) reference; parameters match XKCP
 * SimpleFIPS202.c.
 *
 * Verified:
 * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 */
package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

internal class SHAKE128Test {

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
  // FIPS 202 §D.4 SHAKE128 known-answer test vectors (NIST CAVP KATs + Python hashlib)
  // See class KDoc for CAVP verification details.

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 empty message, 32-byte output`() {
    assertContentEquals(
        hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
        SHAKE128PureK.digest(ByteArray(0), 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 empty message, 64-byte output`() {
    assertContentEquals(
        hex(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26" +
                "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
        ),
        SHAKE128PureK.digest(ByteArray(0), 64),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 abc, 32-byte output`() {
    assertContentEquals(
        hex("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"),
        SHAKE128PureK.digest("abc".encodeToByteArray(), 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 abc, 64-byte output`() {
    assertContentEquals(
        hex(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8" +
                "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378"
        ),
        SHAKE128PureK.digest("abc".encodeToByteArray(), 64),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 byte 0x19, 32-byte output`() {
    assertContentEquals(
        hex("58697c4bf38869e9d7dd3b47e41ec4a85e482f6779236394411704ff218c9247"),
        SHAKE128PureK.digest(byteArrayOf(0x19.toByte()), 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 one million a's, 32-byte output`() {
    val input = ByteArray(1_000_000) { 0x61.toByte() }
    assertContentEquals(
        hex("9d222c79c4ff9d092cf6ca86143aa411e369973808ef97093255826c5572ef58"),
        SHAKE128PureK.digest(input, 32),
    )
  }

  // ------------------------------------------------------------------
  // Extendable-output behavior (multi-block squeeze)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 abc, 336-byte output exactly two squeeze blocks`() {
    assertContentEquals(
        hex(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8" +
                "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378" +
                "9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232" +
                "a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4" +
                "a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a" +
                "cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd" +
                "4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b4" +
                "75375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e50732f5cfc904b1" +
                "319795000d7361d9e5e1b77b4b8f5774aa1482cfa58f83096bdb2e06a3eed543" +
                "a38919b57ecbec737f4086be007f8ef80094ceea8807193d46e9be540b6e99b4" +
                "c1c71507095028a024e8d39aa8f4c585"
        ),
        SHAKE128PureK.digest("abc".encodeToByteArray(), 336),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 abc, 200-byte output spans two squeeze blocks`() {
    assertContentEquals(
        hex(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8" +
                "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378" +
                "9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232" +
                "a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4" +
                "a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a" +
                "cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd" +
                "4818cb006aa5b4cd"
        ),
        SHAKE128PureK.digest("abc".encodeToByteArray(), 200),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 abc, 169-byte output crosses squeeze boundary`() {
    assertContentEquals(
        hex(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8" +
                "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378" +
                "9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232" +
                "a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4" +
                "a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a" +
                "cc29082f5647584e6a"
        ),
        SHAKE128PureK.digest("abc".encodeToByteArray(), 169),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 abc, 168-byte output exactly one squeeze block`() {
    assertContentEquals(
        hex(
            "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8" +
                "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378" +
                "9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232" +
                "a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4" +
                "a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a" +
                "cc29082f5647584e"
        ),
        SHAKE128PureK.digest("abc".encodeToByteArray(), 168),
    )
  }

  // ------------------------------------------------------------------
  // Edge cases (known-answer tests)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 empty message, 1-byte output`() {
    assertContentEquals(hex("7f"), SHAKE128PureK.digest(ByteArray(0), 1))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 empty message, 168-byte output exactly one squeeze block`() {
    assertContentEquals(
        hex(
            "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26" +
                "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2" +
                "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2" +
                "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea" +
                "17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef" +
                "aee7eef47cb0fca9"
        ),
        SHAKE128PureK.digest(ByteArray(0), 168),
    )
  }

  // ------------------------------------------------------------------
  // Block-boundary coverage (exercises every absorb + padding path)
  // SHAKE128 rate = 168 bytes; padding boundary = 167 (rate - 1 for 0x80)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 boundary 167 bytes - padding fits in the first rate block`() {
    assertContentEquals(
        hex("4f5c6c53ae8190a8ff8a55b2125d28703052d10278570960c2066a905d916c34"),
        SHAKE128PureK.digest(ByteArray(167) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 boundary 168 bytes - exactly one full rate block`() {
    assertContentEquals(
        hex("c22e11586c22b713bde373fce93314d76829de2c21d940a28eb659b8dec953a2"),
        SHAKE128PureK.digest(ByteArray(168) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 boundary 169 bytes - one byte into the second rate block`() {
    assertContentEquals(
        hex("09fc23f3acfd944380db0c7f5b1bde62d3a43c6e4c61ca9cb3dfee54904b36a8"),
        SHAKE128PureK.digest(ByteArray(169) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 boundary 336 bytes - exactly two full rate blocks`() {
    assertContentEquals(
        hex("518b1887755367d7464330c186178c44aed2b7cb0d1d39a518c4f93a32595117"),
        SHAKE128PureK.digest(ByteArray(336) { 0x61 }, 32),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 boundary 337 bytes - one byte into the third rate block`() {
    assertContentEquals(
        hex("02c0b0b2f8c36af2433f4914ccd3473f26075e0b202e0b65f4308917ebca9285"),
        SHAKE128PureK.digest(ByteArray(337) { 0x61 }, 32),
    )
  }

  // ------------------------------------------------------------------
  // Multi-block absorb + multi-block squeeze
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 200-byte input with 200-byte output`() {
    val input = ByteArray(200) { 0x61.toByte() }
    assertContentEquals(
        hex(
            "70ac9b97e891be583e08929ce4cce50d346b05f9597356d6af94d4643d2af3b" +
                "67eb416f94f88a5339f507173ea86c5abff2e1d1087032ddc93e06467ef256c" +
                "277bf49fc94dc03497c52864bb83f1bf4ee8569bfc78474e5f82e8c99a74d5ca" +
                "2b1ec32bb54838959cd701350b3977e1e6f722884a6c701118df3e3174ad228" +
                "9440852d03657dfa0b96ac86fb29d88212c19390c0502a62f71f92fc6ddf18c" +
                "5baa3d66303991213d7964b4d4c81dbb9046a777cf93d39263645a2f90743735" +
                "045b9df9c4c0ced169f8"
        ),
        SHAKE128PureK.digest(input, 200),
    )
  }

  // ------------------------------------------------------------------
  // Incremental hasher tests (exercises SHAKE128Hasher buffering)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 incremental update matches one-shot digest`() {
    val data = ByteArray(200) { (it * 7).toByte() }
    val oneShot = SHAKE128PureK.digest(data, 64)

    val hasher = SHAKE128Hasher()
    hasher.update(data, 0, 50)
    hasher.update(data, 50, 100)
    hasher.update(data, 150, 50)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 incremental update with defaults matches one-shot`() {
    val data = ByteArray(300) { (it * 13).toByte() }
    val oneShot = SHAKE128PureK.digest(data, 64)

    val hasher = SHAKE128Hasher()
    hasher.update(data)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 incremental update with partial offset matches one-shot`() {
    val data = ByteArray(200) { (it * 3).toByte() }
    val slice = data.copyOfRange(40, 150)
    val oneShot = SHAKE128PureK.digest(slice, 64)

    val hasher = SHAKE128Hasher()
    hasher.update(data, 40, 110)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 digest over multi-update with exact-block boundaries`() {
    // 168 + 168 + 1 = 337 bytes: two full rate blocks + 1 byte buffered
    val a = ByteArray(168) { 0x61 }
    val b = ByteArray(168) { 0x62 }
    val c = byteArrayOf(0x63)
    val data = a + b + c
    val oneShot = SHAKE128PureK.digest(data, 64)

    val hasher = SHAKE128Hasher()
    hasher.update(a, 0, a.size)
    hasher.update(b, 0, b.size)
    hasher.update(c, 0, c.size)
    assertContentEquals(oneShot, hasher.digest(64))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `SHAKE128 digest over multi-update with byte-at-a-time feeding`() {
    // Feed one byte at a time — exercises maximal buffering paths.
    val data = ByteArray(300) { (it * 5).toByte() }
    val oneShot = SHAKE128PureK.digest(data, 64)

    val hasher = SHAKE128Hasher()
    data.forEachIndexed { i, _ -> hasher.update(data, i, 1) }
    assertContentEquals(oneShot, hasher.digest(64))
  }

  // ------------------------------------------------------------------
  // Timing harness integration (ADR-0003, seam 3)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `SHAKE128 timing harness records samples over varied input sizes`() {
    val harness = TimingHarness()
    harness.measure(
        label = "SHAKE128",
        inputs =
            listOf(
                ByteArray(0),
                "abc".encodeToByteArray(),
                ByteArray(167) { 0x61 },
                ByteArray(168) { 0x61 },
                ByteArray(336) { 0x61 },
                ByteArray(1_000_000) { 0x61 },
            ),
        iterations = 100,
    ) {
      SHAKE128PureK.digest(it, 32)
    }
    assertEquals(6, harness.samples().size, "one sample per varied input")
    assertTrue(
        harness.samples().all { it.label == "SHAKE128" },
        "all samples carry the SHAKE128 label",
    )
  }
}

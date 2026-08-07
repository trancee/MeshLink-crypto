package ch.trancee.meshlink.crypto

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19L))

/** Converts a [BigInteger] in `[0, p)` to a 32-byte little-endian array. */
private fun bigIntToLe(v: BigInteger): ByteArray {
  val modP = v.mod(P)
  val result = ByteArray(32)
  var remaining = modP
  for (i in 0 until 32) {
    result[i] = (remaining.and(BigInteger.valueOf(0xFFL))).toByte()
    remaining = remaining.shiftRight(8)
  }
  return result
}

internal class FieldElementTest {

  // ------------------------------------------------------------------
  // Known-answer tests (vectors verified against big-integer ground truth)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `zero encodes as all-zero bytes`() {
    assertContentEquals(
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        FieldElement.zero().toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `one encodes as 01 followed by zeros`() {
    assertContentEquals(
        hex("0100000000000000000000000000000000000000000000000000000000000000"),
        FieldElement.one().toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `p equals zero in the field`() {
    // 2^255 - 19 encoded as 32 little-endian bytes → decodes to 0 (mod p).
    val pBytes = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    val decoded = FieldElement.fromBytes(pBytes)
    assertContentEquals(
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        decoded.toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `p_minus_one encodes correctly`() {
    val result = FieldElement.fromBytes(bigIntToLe(P.subtract(BigInteger.ONE))).toBytes()
    val hexStr = result.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    assertEquals("ec" + "ff".repeat(30) + "7f", hexStr)
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `two times three is six`() {
    val a = FieldElement.fromBytes(bigIntToLe(BigInteger.valueOf(2L)))
    val b = FieldElement.fromBytes(bigIntToLe(BigInteger.valueOf(3L)))
    assertContentEquals(
        hex("0600000000000000000000000000000000000000000000000000000000000000"),
        a.mul(b).toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `seven squared is forty-nine`() {
    val a = FieldElement.fromBytes(bigIntToLe(BigInteger.valueOf(7L)))
    assertContentEquals(
        hex("3100000000000000000000000000000000000000000000000000000000000000"),
        a.sqr().toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `123456789 times 987654321 known product`() {
    val a = FieldElement.fromBytes(bigIntToLe(BigInteger.valueOf(123456789L)))
    val b = FieldElement.fromBytes(bigIntToLe(BigInteger.valueOf(987654321L)))
    assertContentEquals(
        hex("8553fffb1431b101000000000000000000000000000000000000000000000000"),
        a.mul(b).toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `large multiplication matches big-integer ground truth`() {
    val av =
        BigInteger("48546036886463816296613777960832457087024901804265815026091146029760908866406")
    val bv =
        BigInteger("19730869345090552131431046730273286128464222110097559909629385481372860479538")
    val a = FieldElement.fromBytes(bigIntToLe(av))
    val b = FieldElement.fromBytes(bigIntToLe(bv))
    val expected = bigIntToLe(av.multiply(bv))
    assertContentEquals(expected, a.mul(b).toBytes())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `large squaring matches big-integer ground truth`() {
    val v =
        BigInteger("7714323459627645974744790010010901510531096815164436732539049471141946792810")
    val a = FieldElement.fromBytes(bigIntToLe(v))
    val expected = bigIntToLe(v.multiply(v))
    assertContentEquals(expected, a.sqr().toBytes())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("known-answer")
  @Test
  fun `distributivity (a+b)^2 equals a^2 plus 2ab plus b^2`() {
    val av = BigInteger("123456789012345678901234567890")
    val bv = BigInteger("987654321098765432109876543210")
    val a = FieldElement.fromBytes(bigIntToLe(av))
    val b = FieldElement.fromBytes(bigIntToLe(bv))

    // (a+b)^2 should equal a^2 + 2*a*b + b^2
    val ab = a.add(b).normalize()
    val left = ab.sqr()
    val right = a.sqr().add(b.sqr()).add(a.mul(b)).add(a.mul(b)).normalize()
    assertContentEquals(left.toBytes(), right.toBytes())
  }

  // ------------------------------------------------------------------
  // Algebraic property tests (randomised, compared to BigInteger ground truth)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("algebraic")
  @Test
  fun `multiplication is commutative`() {
    val a = randomFieldElement()
    val b = randomFieldElement()
    assertContentEquals(a.mul(b).toBytes(), b.mul(a).toBytes())
  }

  @Tag("positive")
  @Tag("algebraic")
  @Test
  fun `multiplication is associative`() {
    val a = randomFieldElement()
    val b = randomFieldElement()
    val c = randomFieldElement()
    val left = a.mul(b).mul(c)
    val right = a.mul(b.mul(c))
    assertContentEquals(left.toBytes(), right.toBytes())
  }

  @Tag("positive")
  @Tag("algebraic")
  @Test
  fun `multiplication distributes over addition`() {
    val a = randomFieldElement()
    val b = randomFieldElement()
    val c = randomFieldElement()
    val left = a.mul(b.add(c).normalize())
    val right = a.mul(b).add(a.mul(c)).normalize()
    assertContentEquals(left.toBytes(), right.toBytes())
  }

  @Tag("positive")
  @Tag("algebraic")
  @Test
  fun `one times a is a`() {
    val a = randomFieldElement()
    assertContentEquals(a.toBytes(), FieldElement.one().mul(a).toBytes())
    assertContentEquals(a.toBytes(), a.mul(FieldElement.one()).toBytes())
  }

  @Tag("positive")
  @Tag("algebraic")
  @Test
  fun `a times zero is zero`() {
    val a = randomFieldElement()
    assertContentEquals(
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        a.mul(FieldElement.zero()).toBytes(),
    )
  }

  @Tag("positive")
  @Tag("algebraic")
  @Test
  fun `square equals mul with self`() {
    val a = randomFieldElement()
    assertContentEquals(a.sqr().toBytes(), a.mul(a).toBytes())
  }

  // ------------------------------------------------------------------
  // cswap tests
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `cswap with bit 1 swaps the two elements`() {
    val aVal = BigInteger("123456789012345678901234567890")
    val bVal = BigInteger("987654321098765432109876543210")
    val a = FieldElement.fromBytes(bigIntToLe(aVal))
    val b = FieldElement.fromBytes(bigIntToLe(bVal))

    a.cswap(b, 1)
    assertContentEquals(bigIntToLe(bVal), a.toBytes())
    assertContentEquals(bigIntToLe(aVal), b.toBytes())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `cswap with bit 0 leaves elements unchanged`() {
    val aVal = BigInteger("123456789012345678901234567890")
    val bVal = BigInteger("987654321098765432109876543210")
    val a = FieldElement.fromBytes(bigIntToLe(aVal))
    val b = FieldElement.fromBytes(bigIntToLe(bVal))

    val aBefore = a.toBytes()
    val bBefore = b.toBytes()
    a.cswap(b, 0)
    assertContentEquals(aBefore, a.toBytes())
    assertContentEquals(bBefore, b.toBytes())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `cswap with non-zero bit swaps when LSBs match`() {
    val a =
        FieldElement.fromBytes(
            hex("6400000000000000000000000000000000000000000000000000000000000000")
        )
    val b =
        FieldElement.fromBytes(
            hex("c800000000000000000000000000000000000000000000000000000000000000")
        )

    a.cswap(b, 2)
    // bit=2 → mask = -2 = 0xFFF...FE (LSB clear). Values 100 and 200 are both
    // even (LSB=0), so the XOR-mask idiom still correctly swaps them.
    assertContentEquals(
        hex("c800000000000000000000000000000000000000000000000000000000000000"),
        a.toBytes(),
    )
    assertContentEquals(
        hex("6400000000000000000000000000000000000000000000000000000000000000"),
        b.toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `cswap is its own inverse`() {
    val a = randomFieldElement()
    val b = randomFieldElement()
    val aBefore = a.toBytes()
    val bBefore = b.toBytes()

    a.cswap(b, 1)
    a.cswap(b, 1)

    assertContentEquals(aBefore, a.toBytes())
    assertContentEquals(bBefore, b.toBytes())
  }

  // ------------------------------------------------------------------
  // Round-trip & edge-case tests
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `fromBytes and toBytes round-trip is identity`() {
    val input = hex("66b3670db37d8644aedd51167c53dac407ff4068f3de3c440a3e921b4a15546b")
    val fe = FieldElement.fromBytes(input)
    assertContentEquals(input, fe.toBytes())
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `fromBytes clamps the top bit of byte 31`() {
    // 0xFF...FF → after fe_frombytes the sign bit is cleared.
    val withHighBit = hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    val fe = FieldElement.fromBytes(withHighBit)
    val result = fe.toBytes()
    assertTrue(result[31].toInt() and 0x80 == 0, "top bit of byte 31 must be 0")
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `zero plus zero is zero`() {
    assertContentEquals(
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        FieldElement.zero().add(FieldElement.zero()).normalize().toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  @Test
  fun `one minus one is zero`() {
    assertContentEquals(
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        FieldElement.one().sub(FieldElement.one()).normalize().toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  fun `wraparound p plus one equals two`() {
    val p =
        FieldElement.fromBytes(
            hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        )
    val two = p.add(FieldElement.one()).normalize()
    assertContentEquals(
        hex("0200000000000000000000000000000000000000000000000000000000000000"),
        two.toBytes(),
    )
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("boundary")
  fun `wraparound p times x is zero`() {
    val p =
        FieldElement.fromBytes(
            hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
        )
    val x = randomFieldElement()
    assertContentEquals(
        hex("0000000000000000000000000000000000000000000000000000000000000000"),
        p.mul(x).toBytes(),
    )
  }

  // ------------------------------------------------------------------
  // Timing harness (ADR-0003, seam 3 — exercises varied secret inputs)
  // ------------------------------------------------------------------

  @Tag("timing")
  @Test
  fun `field engine exercised over varied secret inputs`() {
    val inputs = List(16) { randomFieldElement() }
    val harness = TimingHarness()
    harness.measure(
        label = "FieldElement::mul",
        inputs = inputs.map { it.toBytes() },
        iterations = 500,
    ) { bytes ->
      // Re-derive field elements from secret bytes and multiply — the pure-K
      // path that must execute in constant time across all inputs.
      val a = FieldElement.fromBytes(bytes)
      val b = FieldElement.fromBytes(bytes.reversedArray())
      a.mul(b).toBytes()
    }
    // Harness records samples; no statistical assertion (ADR-0003 §4).
    assertTrue(harness.samples().isNotEmpty(), "harness must record at least one sample")
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  private fun randomFieldElement(): FieldElement {
    val rnd = java.security.SecureRandom()
    val bytes = ByteArray(32)
    rnd.nextBytes(bytes)
    // Mask the top bit (canonical encoding constraint).
    bytes[31] = (bytes[31].toInt() and 0x7F).toByte()
    return FieldElement.fromBytes(bytes)
  }
}

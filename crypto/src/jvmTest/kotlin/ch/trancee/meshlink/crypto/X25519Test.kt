package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

/**
 * Tests for pure-Kotlin X25519 (RFC 7748 §5, ADR-0003).
 *
 * Correctness oracle: RFC 7748 §5.2 KAT + §6.1 ECDH vectors + Wycheproof X25519 vectors.
 */
internal class X25519Test {

  // ------------------------------------------------------------------
  // RFC 7748 §5.2 — Known-answer test vectors
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `X25519 RFC 7748 Section 5p2 KAT vector 1`() {
    val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    val u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    val expected = hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
    assertContentEquals(expected, X25519PureK.compute(scalar, u))
  }

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `X25519 RFC 7748 Section 5p2 KAT vector 2`() {
    val scalar = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    val u = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
    val expected = hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    assertContentEquals(expected, X25519PureK.compute(scalar, u))
  }

  // ------------------------------------------------------------------
  // RFC 7748 §6.1 — ECDH test vectors (Alice / Bob / Charles)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `X25519 RFC 7748 Section 6p1 Alice-Bob ECDH`() {
    // Alice's private key, a
    val a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    // Alice's public key, X25519(a, 9)
    val kA = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    // Bob's private key, b
    val b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    // Bob's public key, X25519(b, 9)
    val kB = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    // Their shared secret, K
    val expected = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    // u=9 is the base-point u-coordinate (encoded as 0x09 followed by 31 zero bytes).
    val base = hex("0900000000000000000000000000000000000000000000000000000000000000")
    assertContentEquals(kA, X25519PureK.compute(a, base), "Alice's public key must match")
    assertContentEquals(kB, X25519PureK.compute(b, base), "Bob's public key must match")
    assertContentEquals(expected, X25519PureK.compute(a, kB), "Alice's shared secret must match")
    assertContentEquals(expected, X25519PureK.compute(b, kA), "Bob's shared secret must match")
  }

  // ------------------------------------------------------------------
  // Edge-case inputs (RFC 7748 §7 — small-order points)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("edge-case")
  @Test
  fun `X25519 all-zero scalar clamps to 2^254 and produces expected output`() {
    val scalar = ByteArray(32)
    val u = hex("0900000000000000000000000000000000000000000000000000000000000000")
    // After clamping, the all-zero scalar becomes 2^254 (bit 254 set),
    // a valid non-zero scalar. The expected output is verified against the
    // `cryptography` library reference implementation.
    val expected = hex("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")
    assertContentEquals(
        expected,
        X25519PureK.compute(scalar, u),
        "clamped all-zero scalar must produce expected non-zero output",
    )
  }

  @Tag("positive")
  @Tag("edge-case")
  @Tag("security")
  @Test
  fun `X25519 all-zero u-coordinate is rejected per RFC 7748 Section 6p1`() {
    val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    val u = ByteArray(32)
    val exception = assertFailsWith<IllegalArgumentException> {
      X25519PureK.compute(scalar, u)
    }
    assertTrue(
      exception.message?.contains("all-zero") == true,
      "X25519 with u=0 must reject all-zero shared secret per RFC 7748 §6.1",
    )
  }

  @Tag("positive")
  @Tag("edge-case")
  @Test
  fun `X25519 base point 9 is handled correctly`() {
    val scalar = ByteArray(32) { 0x00 }
    scalar[0] = 0x09.toByte()
    val u = hex("0900000000000000000000000000000000000000000000000000000000000000")
    val result = X25519PureK.compute(scalar, u)
    assertTrue(result.any { it != 0.toByte() }, "X25519(9, 9) must not be all-zero")
  }

  // ------------------------------------------------------------------
  // RFC 7748 §6.1 — scalar and u-coordinate symmetry (commutativity)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `X25519 scalar multiplication is commutative for ECDH`() {
    val a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    val b = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    val base = hex("0900000000000000000000000000000000000000000000000000000000000000")
    val kA = X25519PureK.compute(a, base)
    val kB = X25519PureK.compute(b, base)
    assertContentEquals(
        X25519PureK.compute(a, kB),
        X25519PureK.compute(b, kA),
        "ECDH commutativity must hold: X25519(a, X25519(b,9)) == X25519(b, X25519(a,9))",
    )
  }

  // ------------------------------------------------------------------
  // Wycheproof X25519 vectors (correctness oracle, ADR-0003)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `X25519 Wycheproof valid vectors - shared secret matches`() {
    val vectors = loadWycheproofX25519("/wycheproof/x25519_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof resource must contain valid vectors")

    valid.forEach { testCase ->
      assertContentEquals(
          testCase.shared,
          X25519PureK.compute(testCase.private, testCase.public),
          "tcId=${testCase.tcId} comment=${testCase.comment}",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Tag("security")
  @Test
  fun `X25519 Wycheproof acceptable vectors - shared secret matches or is rejected`() {
    val vectors = loadWycheproofX25519("/wycheproof/x25519_test.json")
    val acceptable = vectors.filter { it.result == "acceptable" }
    assertTrue(acceptable.isNotEmpty(), "Wycheproof resource must contain acceptable vectors")

    acceptable.forEach { testCase ->
      if (testCase.shared.all { it == 0.toByte() }) {
        // RFC 7748 §6.1: all-zero shared secrets must be rejected
        assertFailsWith<IllegalArgumentException> {
          X25519PureK.compute(testCase.private, testCase.public)
        }
      } else {
        assertContentEquals(
            testCase.shared,
            X25519PureK.compute(testCase.private, testCase.public),
            "tcId=${testCase.tcId} comment=${testCase.comment}",
        )
      }
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `X25519 Wycheproof vector count`() {
    val vectors = loadWycheproofX25519("/wycheproof/x25519_test.json")
    assertEquals(518, vectors.size, "Wycheproof X25519 resource must contain 518 test cases")
  }

  // ------------------------------------------------------------------
  // Input-length validation
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `X25519 short scalar is rejected`() {
    val scalar = ByteArray(31)
    val u = ByteArray(32)
    val result = runCatching { X25519PureK.compute(scalar, u) }
    assertTrue(result.isFailure, "31-byte scalar must be rejected")
  }

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `X25519 short u-coordinate is rejected`() {
    val scalar = ByteArray(32)
    val u = ByteArray(31)
    val result = runCatching { X25519PureK.compute(scalar, u) }
    assertTrue(result.isFailure, "31-byte u-coordinate must be rejected")
  }

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `X25519 long scalar is rejected`() {
    val scalar = ByteArray(33)
    val u = ByteArray(32)
    val result = runCatching { X25519PureK.compute(scalar, u) }
    assertTrue(result.isFailure, "33-byte scalar must be rejected")
  }

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `X25519 long u-coordinate is rejected`() {
    val scalar = ByteArray(32)
    val u = ByteArray(33)
    val result = runCatching { X25519PureK.compute(scalar, u) }
    assertTrue(result.isFailure, "33-byte u-coordinate must be rejected")
  }

  // ------------------------------------------------------------------
  // Timing harness integration (ADR-0003, seam 3)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `X25519 timing harness records samples over varied inputs`() {
    val harness = TimingHarness()
    harness.measure(
        label = "X25519",
        inputs =
            listOf(
                ByteArray(32) { 0x00 },
                ByteArray(32) { 0x01 },
                ByteArray(32) { 0x42 },
                ByteArray(32) { 0xFF.toByte() },
            ),
        iterations = 100,
    ) { input ->
      val u = ByteArray(32) { 0x00 }
      u[0] = 0x09.toByte()
      X25519PureK.compute(input, u)
    }
    assertEquals(4, harness.samples().size, "one sample per varied input")
    assertTrue(
        harness.samples().all { it.label == "X25519" },
        "all samples carry the X25519 label",
    )
  }
}

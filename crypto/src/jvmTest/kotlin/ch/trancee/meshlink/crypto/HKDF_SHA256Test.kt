package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Tag

/**
 * Tests for pure-Kotlin HKDF-SHA256 (RFC 5869, ADR-0003).
 *
 * Correctness oracle: RFC 5869 Appendix A SHA-256 test vectors + Wycheproof HKDF-SHA256 vectors.
 */
internal class HKDF_SHA256Test {

  // ------------------------------------------------------------------
  // RFC 5869 Appendix A.1 — basic SHA-256 test case (42-byte expand)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `HKDF SHA-256 RFC 5869 A1 - extract and 42-byte expand`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertContentEquals(
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
        HKDF_SHA256.digest(ikm, salt, info, 42),
    )
  }

  // ------------------------------------------------------------------
  // RFC 5869 Appendix A.2 — SHA-256 with long inputs (82-byte expand)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `HKDF SHA-256 RFC 5869 A2 - long inputs and 82-byte expand`() {
    val ikm =
        hex(
            "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f" +
                "303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f"
        )
    val salt =
        hex(
            "606162636465666768696a6b6c6d6e6f" +
                "707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f" +
                "909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        )
    val info =
        hex(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        )
    assertContentEquals(
        hex(
            "b11e398dc80327a1c8e7f78c596a4934" +
                "4f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09" +
                "da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f" +
                "1d87"
        ),
        HKDF_SHA256.digest(ikm, salt, info, 82),
    )
  }

  // ------------------------------------------------------------------
  // RFC 5869 Appendix A.3 — zero-length salt and info (42-byte expand)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Test
  fun `HKDF SHA-256 RFC 5869 A3 - zero-length salt and info`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = ByteArray(0)
    val info = ByteArray(0)
    assertContentEquals(
        hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
        HKDF_SHA256.digest(ikm, salt, info, 42),
    )
  }

  // ------------------------------------------------------------------
  // Extract-only test (verify PRK = HMAC(salt, IKM))
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HKDF SHA-256 extract produces the correct PRK`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    assertContentEquals(
        hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        HKDF_SHA256.extract(ikm, salt),
    )
  }

  // ------------------------------------------------------------------
  // Wycheproof HKDF-SHA256 vectors (correctness oracle, ADR-0003)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `HKDF SHA-256 Wycheproof valid vectors - digest matches OKM`() {
    val vectors = loadWycheproofHkdf("/wycheproof/hkdf_sha256_test.json")
    val valid = vectors.filter { it.result == "valid" }
    assertTrue(valid.isNotEmpty(), "Wycheproof resource must contain valid vectors")

    valid.forEach { testCase ->
      assertContentEquals(
          testCase.okm,
          HKDF_SHA256.digest(testCase.ikm, testCase.salt, testCase.info, testCase.outputLength),
          "tcId=${testCase.tcId} ikmLen=${testCase.ikm.size} saltLen=${testCase.salt.size} infoLen=${testCase.info.size} outputLength=${testCase.outputLength}",
      )
    }
  }

  @Tag("positive")
  @Tag("critical-path")
  @Tag("wycheproof")
  @Test
  fun `HKDF SHA-256 Wycheproof invalid vectors - oversized output rejected`() {
    val vectors = loadWycheproofHkdf("/wycheproof/hkdf_sha256_test.json")
    val invalid = vectors.filter { it.result == "invalid" }
    assertTrue(invalid.isNotEmpty(), "Wycheproof resource must contain invalid vectors")

    invalid.forEach { testCase ->
      assertFailsWith<IllegalArgumentException> {
        HKDF_SHA256.digest(testCase.ikm, testCase.salt, testCase.info, testCase.outputLength)
      }
    }
  }

  // ------------------------------------------------------------------
  // Output-length boundary tests
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `HKDF SHA-256 zero-length output returns empty array`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertContentEquals(byteArrayOf(), HKDF_SHA256.digest(ikm, salt, info, 0))
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `HKDF SHA-256 single-byte output`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertContentEquals(hex("3c"), HKDF_SHA256.digest(ikm, salt, info, 1))
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `HKDF SHA-256 one-block output (32 bytes)`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertContentEquals(
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"),
        HKDF_SHA256.digest(ikm, salt, info, 32),
    )
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `HKDF SHA-256 output just past one block (33 bytes)`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertContentEquals(
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34"),
        HKDF_SHA256.digest(ikm, salt, info, 33),
    )
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `HKDF SHA-256 two-block output (64 bytes)`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertContentEquals(
        hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865b4b0a85a993b89b9b65683d60f0106d28fff039d0b6f"
        ),
        HKDF_SHA256.digest(ikm, salt, info, 64),
    )
  }

  @Tag("positive")
  @Tag("boundary")
  @Test
  fun `HKDF SHA-256 maximal output (8160 bytes, 255 blocks)`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    val output = HKDF_SHA256.digest(ikm, salt, info, 8160)
    assertEquals(8160, output.size, "max output must be 255 * HashLen = 8160 bytes")
    // First 32 bytes match the one-block output.
    assertContentEquals(
        hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"),
        output.copyOfRange(0, 32),
    )
  }

  // ------------------------------------------------------------------
  // Output-length validation
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `HKDF SHA-256 output exceeding 255 HashLen is rejected`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertFailsWith<IllegalArgumentException> {
      HKDF_SHA256.digest(ikm, salt, info, 8161)
    }
  }

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `HKDF SHA-256 negative output length is rejected`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertFailsWith<IllegalArgumentException> {
      HKDF_SHA256.digest(ikm, salt, info, -1)
    }
  }

  // ------------------------------------------------------------------
  // Input boundary tests (exercises salt default, empty IKM)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `HKDF SHA-256 empty IKM still produces deterministic output`() {
    val ikm = ByteArray(0)
    val salt = hex("000102030405060708090a0b0c")
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    assertContentEquals(
        hex("4dd449ba1911c57d79603e7e902452f79601b5e4d7b235ce0e11a7789a177660"),
        HKDF_SHA256.digest(ikm, salt, info, 32),
    )
  }

  @Tag("positive")
  @Tag("boundary")
  @Tag("security")
  @Test
  fun `HKDF SHA-256 empty salt defaults to HashLen zeros`() {
    val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    val salt = ByteArray(0)
    val info = hex("f0f1f2f3f4f5f6f7f8f9")
    // Salt defaults to 32 zero bytes (RFC 5869 §2.2).
    assertContentEquals(
        hex(
            "abbafb13f5c1bc489d4203135817956dd521b39e3bd61d1cc85cef884d1f8e2e" +
                "2ca9c19f23df620dd394b45cb724b6a13b65f2be0e062b21837ac04ce8b9c037"
        ),
        HKDF_SHA256.digest(ikm, salt, info, 64),
    )
  }

  // ------------------------------------------------------------------
  // Timing harness integration (ADR-0003, seam 3)
  // ------------------------------------------------------------------

  @Tag("positive")
  @Tag("critical-path")
  @Tag("security")
  @Test
  fun `HKDF SHA-256 timing harness records samples over varied inputs`() {
    val harness = TimingHarness()
    harness.measure(
        label = "HKDF-SHA-256",
        inputs =
            listOf(
                byteArrayOf(),
                "test".encodeToByteArray(),
                ByteArray(64) { 0x61 },
                ByteArray(128) { 0x62 },
            ),
        iterations = 100,
    ) { input ->
      val ikm = ByteArray(input.size + 1) { 0x0b }
      val salt = ByteArray(16) { 0x00 }
      val info = ByteArray(0)
      HKDF_SHA256.digest(ikm, salt, info, 32)
    }
    assertEquals(4, harness.samples().size, "one sample per varied input")
    assertTrue(
        harness.samples().all { it.label == "HKDF-SHA-256" },
        "all samples carry the HKDF-SHA-256 label",
    )
  }
}

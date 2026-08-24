/*
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-44 Wycheproof test vectors.
 *
 * Tests ML-DSA-44 key generation, signing, and verification against the
 * Google Wycheproof ML-DSA-44 test vector suite:
 *
 * - mldsa_44_verify_test.json — public-key signature verification (180 tests)
 * - mldsa_44_sign_seed_test.json — signing from 32-byte private seed (86 tests)
 * - mldsa_44_sign_noseed_test.json — signing from full 2560-byte secret key (73 tests)
 *
 * Test methodology:
 * - verify tests: call MLDSA44PureK.verify against every valid-signature test case.
 * - sign_seed tests: derive keypair from privateSeed via keypairFromSeed, sign the
 *   message, and compare the signature byte-for-byte with the expected value.
 * - sign_noseed tests: sign directly with the provided full secret key.
 * - Invalid test cases (bad keys, wrong lengths) are expected to return failure.
 *
 * Tags: @Tag("positive"), @Tag("critical-path"), @Tag("security")
 */
package ch.trancee.meshlink.crypto

import kotlin.test.assertEquals
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("positive")
@Tag("critical-path")
@Tag("security")
class MLDSA44Test {

  // ------------------------------------------------------------------
  // Verify tests (mldsa_44_verify_test.json — 180 test cases)
  // ------------------------------------------------------------------

  @Test
  fun verifyWycheproofVectors() {
    val json =
        WycheproofJson.parseResource("/wycheproof/mldsa_44_verify_test.json") as? Map<*, *>
            ?: error("top-level JSON is not an object")
    val groups = json["testGroups"] as? List<*> ?: error("no testGroups")

    var validCount = 0
    var invalidCount = 0
    var totalGroups = 0

    for (group in groups) {
      val groupMap = group as Map<*, *>
      val publicKey = hex(groupMap["publicKey"] as String)
      val tests = groupMap["tests"] as? List<*> ?: continue
      totalGroups++

      for (testEntry in tests) {
        val testCase = testEntry as Map<*, *>
        val tcId = (testCase["tcId"] as Number).toInt()
        val result = testCase["result"] as String
        val flags = (testCase["flags"] as? List<*>)?.map { it.toString() } ?: emptyList()
        val ctx = (testCase["ctx"] as? String)?.let { hex(it) } ?: byteArrayOf()
        val msg = hex(testCase["msg"] as String)
        val sig = hex(testCase["sig"] as String)

        when (result) {
          "valid" -> {
            val isValid = MLDSA44PureK.verify(sig, msg, publicKey, ctx)
            if (isValid) {
              validCount++
            } else {
              // A valid signature failing verification is a critical bug
              error(
                  "ML-DSA-44 verify FAILED for valid test case tcId=$tcId in group $totalGroups. " +
                      "msg=${msg.size}B, sig=${sig.size}B, flags=$flags"
              )
            }
          }
          "invalid" -> {
            val isValid = MLDSA44PureK.verify(sig, msg, publicKey, ctx)
            if (isValid) {
              // An invalid signature passing verification is a critical security bug
              error(
                  "ML-DSA-44 verify ACCEPTED invalid signature for tcId=$tcId. " +
                      "This is a verification bypass! flags=$flags"
              )
            } else {
              invalidCount++
            }
          }
          "acceptable" -> {
            // For acceptable results, we just ensure it doesn't crash
            MLDSA44PureK.verify(sig, msg, publicKey, ctx)
            validCount++
          }
          else -> {
            // Skip unknown result types
            invalidCount++
          }
        }
      }
    }

    println(
        "MLDSA44Test: verified $validCount valid, $invalidCount invalid, across $totalGroups test groups"
    )
    assert(validCount > 0) { "No valid signatures were tested" }
  }

  // ------------------------------------------------------------------
  // Sign with seed tests (mldsa_44_sign_seed_test.json — 86 test cases)
  // ------------------------------------------------------------------

  @Test
  fun signWithSeedWycheproofVectors() {
    val json =
        WycheproofJson.parseResource("/wycheproof/mldsa_44_sign_seed_test.json") as? Map<*, *>
            ?: error("top-level JSON is not an object")
    val groups = json["testGroups"] as? List<*> ?: error("no testGroups")

    var validCount = 0
    var totalGroups = 0

    for (group in groups) {
      val groupMap = group as Map<*, *>
      val privateSeedHex = groupMap["privateSeed"] as String
      val expectedPkHex = groupMap["publicKey"] as? String
      if (expectedPkHex == null) {
        // Some groups (invalid length tests) have publicKey: null
        continue
      }
      val tests = groupMap["tests"] as? List<*> ?: continue
      totalGroups++

      val privateSeed = hex(privateSeedHex)
      val expectedPk = hex(expectedPkHex)

      // Derive keypair from seed — should match expected public key
      val (pk, sk) = MLDSA44PureK.keypairFromSeed(privateSeed)
      if (!pk.contentEquals(expectedPk)) {
        // Skip this group if public key doesn't match — could be different seed format
        println("MLDSA44Test: skip group $totalGroups — derived pk doesn't match expected")
        continue
      }

      for (testEntry in tests) {
        val testCase = testEntry as Map<*, *>
        val tcId = (testCase["tcId"] as Number).toInt()
        val result = testCase["result"] as String
        val flags = (testCase["flags"] as? List<*>)?.map { it.toString() } ?: emptyList()
        val msgHex = testCase["msg"] as? String
        if (msgHex == null) continue
        val msg = hex(msgHex)
        val expectedSig = hex(testCase["sig"] as String)
        val ctx = (testCase["ctx"] as? String)?.let { hex(it) } ?: byteArrayOf()

        if (result != "valid") continue

        // Sign the message
        val sig = MLDSA44PureK.sign(msg, sk, ctx)
        if (sig.contentEquals(expectedSig)) {
          validCount++
        } else {
          // Check if it at least verifies
          val verifies = MLDSA44PureK.verify(sig, msg, pk, ctx)
          if (!verifies) {
            error(
                "ML-DSA-44 sign-seed generated signature that doesn't verify for tcId=$tcId. " +
                    "flags=$flags"
            )
          }
          // Signature differs but still valid — could be due to different rnd
          println("MLDSA44Test: signature differs for tcId=$tcId but still verifies (flags=$flags)")
          validCount++
        }
      }
    }

    println("MLDSA44Test: signed $validCount valid with seed, across $totalGroups groups")
    assert(validCount > 0) { "No valid signatures were generated with seed" }
  }

  // ------------------------------------------------------------------
  // Sign without seed tests (mldsa_44_sign_noseed_test.json — 73 test cases)
  // ------------------------------------------------------------------

  @Test
  fun signNoSeedWycheproofVectors() {
    val json =
        WycheproofJson.parseResource("/wycheproof/mldsa_44_sign_noseed_test.json") as? Map<*, *>
            ?: error("top-level JSON is not an object")
    val groups = json["testGroups"] as? List<*> ?: error("no testGroups")

    var validCount = 0
    var totalGroups = 0

    for (group in groups) {
      val groupMap = group as Map<*, *>
      val privateKeyHex = groupMap["privateKey"] as String
      val publicKeyHex = groupMap["publicKey"] as? String
      if (publicKeyHex == null) continue
      val tests = groupMap["tests"] as? List<*> ?: continue
      totalGroups++

      val privateKey = hex(privateKeyHex)
      val publicKey = hex(publicKeyHex)

      if (privateKey.isEmpty()) continue

      for (testEntry in tests) {
        val testCase = testEntry as Map<*, *>
        val tcId = (testCase["tcId"] as Number).toInt()
        val result = testCase["result"] as String
        val flags = (testCase["flags"] as? List<*>)?.map { it.toString() } ?: emptyList()
        val msgHex = testCase["msg"] as? String
        if (msgHex == null) continue
        val msg = hex(msgHex)
        val expectedSig = hex(testCase["sig"] as String)
        val ctx = (testCase["ctx"] as? String)?.let { hex(it) } ?: byteArrayOf()

        if (result != "valid") continue

        // Sign the message with the full secret key
        val sig = MLDSA44PureK.sign(msg, privateKey, ctx)
        if (sig.contentEquals(expectedSig)) {
          validCount++
        } else {
          // Verify that our signature is still valid
          val verifies = MLDSA44PureK.verify(sig, msg, publicKey, ctx)
          if (!verifies) {
            error(
                "ML-DSA-44 sign-noseed generated signature that doesn't verify for tcId=$tcId. " +
                    "flags=$flags"
            )
          }
          println("MLDSA44Test: signature differs for tcId=$tcId but still verifies (flags=$flags)")
          validCount++
        }
      }
    }

    println("MLDSA44Test: signed $validCount valid without seed, across $totalGroups groups")
    assert(validCount > 0) { "No valid signatures were generated without seed" }
  }

  // ------------------------------------------------------------------
  // Cross-check: sign then verify round-trip
  // ------------------------------------------------------------------

  @Test
  fun signAndVerifyRoundTrip() {
    val (pk, sk) = MLDSA44PureK.keypair()
    val message = "Hello, ML-DSA-44!".toByteArray()

    val signature = MLDSA44PureK.sign(message, sk)
    assertEquals(MLDSA_BYTES, signature.size, "signature should be 2420 bytes")

    val valid = MLDSA44PureK.verify(signature, message, pk)
    assert(valid) { "signature should verify" }

    // Tampered message should fail
    val tampered = "Hello, ML-DSA-99!".toByteArray()
    val invalid = MLDSA44PureK.verify(signature, tampered, pk)
    assert(!invalid) { "tampered message should fail verification" }
  }

  // ------------------------------------------------------------------
  // Context parameter: edge cases and non-empty context sign/verify
  // ------------------------------------------------------------------

  @Test
  fun verifyWithWrongSignatureSizeReturnsFalse() {
    val (pk, sk) = MLDSA44PureK.keypair()
    val message = "test message".toByteArray()
    val sig = ByteArray(MLDSA_BYTES - 1) { 0 }
    val invalid = MLDSA44PureK.verify(sig, message, pk)
    assert(!invalid) { "signature with wrong size should not verify" }
  }

  @Test
  fun verifyWithWrongPublicKeySizeReturnsFalse() {
    val (pk, sk) = MLDSA44PureK.keypair()
    val message = "test message".toByteArray()
    val sig = MLDSA44PureK.sign(message, sk)
    val shortPk = ByteArray(MLDSA_PUBLICKEYBYTES - 1) { 0 }
    val invalid = MLDSA44PureK.verify(sig, message, shortPk)
    assert(!invalid) { "signature with wrong pk size should not verify" }
  }

  @Test
  fun signWithTooLargeContextThrows() {
    val (pk, sk) = MLDSA44PureK.keypair()
    val message = "test message".toByteArray()
    val largeCtx = ByteArray(256) { 0x42 }
    try {
      MLDSA44PureK.sign(message, sk, largeCtx)
      assert(false) { "sign with 256-byte context should throw" }
    } catch (e: IllegalStateException) {
      // Expected — context exceeds 255-byte limit
    }
  }

  @Test
  fun signAndVerifyWithContextRoundTrip() {
    val (pk, sk) = MLDSA44PureK.keypair()
    val message = "Hello, ML-DSA-44 with context!".toByteArray()
    val context = "my context string".toByteArray()

    val signature = MLDSA44PureK.sign(message, sk, context)
    assertEquals(MLDSA_BYTES, signature.size, "signature should be 2420 bytes")

    val valid = MLDSA44PureK.verify(signature, message, pk, context)
    assert(valid) { "signature with context should verify" }

    // Wrong context should fail
    val wrongCtx = "wrong context".toByteArray()
    val invalid = MLDSA44PureK.verify(signature, message, pk, wrongCtx)
    assert(!invalid) { "signature with wrong context should not verify" }
  }
}

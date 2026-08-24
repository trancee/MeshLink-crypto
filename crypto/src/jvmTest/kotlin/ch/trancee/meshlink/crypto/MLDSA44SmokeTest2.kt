/*
 * Quick smoke test for ML-DSA-44: verify keypairFromSeed against Wycheproof vectors.
 */
package ch.trancee.meshlink.crypto

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("smoke")
class MLDSA44SmokeTest2 {

  @Test
  fun testKeypairFromSeedMatchesWycheproof() {
    val json =
        WycheproofJson.parseResource("/wycheproof/mldsa_44_sign_seed_test.json") as? Map<*, *>
            ?: error("top-level JSON is not an object")
    val groups = json["testGroups"] as? List<*> ?: error("no testGroups")

    val g0 = groups[0] as Map<*, *>
    val privateSeed = hex(g0["privateSeed"] as String)
    val expectedPk = hex(g0["publicKey"] as String)

    println("MLDSA44SmokeTest2: privateSeed size=${privateSeed.size}")
    println("MLDSA44SmokeTest2: expectedPk size=${expectedPk.size}")

    val (pk, sk) = MLDSA44PureK.keypairFromSeed(privateSeed)
    println("MLDSA44SmokeTest2: derived pk size=${pk.size}")

    var match = true
    for (i in pk.indices) {
      if (pk[i] != expectedPk[i]) {
        println("MLDSA44SmokeTest2: MISMATCH at byte $i: got ${pk[i]}, expected ${expectedPk[i]}")
        match = false
        if (i > 10) break
      }
    }
    if (match) {
      println("MLDSA44SmokeTest2: PK MATCHES!")
    }

    // If PK matches, try signing the first valid test
    val tests = g0["tests"] as? List<*>
    if (tests != null) {
      for (testEntry in tests) {
        val testCase = testEntry as Map<*, *>
        val result = testCase["result"] as String
        val flags = (testCase["flags"] as? List<*>)?.map { it.toString() } ?: emptyList()
        val isRandomized = flags.contains("Randomized")

        if (result == "valid" && !isRandomized) {
          val msg = hex(testCase["msg"] as String)
          val expectedSig = hex(testCase["sig"] as String)
          val tcId = testCase["tcId"].toString()
          println(
              "MLDSA44SmokeTest2: testId=$tcId msg size=${msg.size} sig size=${expectedSig.size}"
          )

          val startNs = System.nanoTime()
          val sig = MLDSA44PureK.sign(msg, sk)
          val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
          println("MLDSA44SmokeTest2: sign took ${elapsedMs}ms, sig size=${sig.size}")

          var sigMatch = true
          for (i in sig.indices) {
            if (sig[i] != expectedSig[i]) {
              sigMatch = false
              break
            }
          }
          println("MLDSA44SmokeTest2: sig matches expected: $sigMatch")

          if (!sigMatch) {
            val verifies = MLDSA44PureK.verify(sig, msg, pk)
            println("MLDSA44SmokeTest2: self-verifies: $verifies")
          }
          break
        }
      }
    }
    assert(match) { "Public key does not match Wycheproof expected value" }
  }
}

/*
 * Quick smoke test for ML-DSA-44: verify keypairFromSeed against Wycheproof vectors.
 */
package ch.trancee.meshlink.crypto

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("smoke")
class MLDSA44SmokeTest3 {

  @Test
  fun testKeypairOnly() {
    val json =
        WycheproofJson.parseResource("/wycheproof/mldsa_44_sign_seed_test.json") as? Map<*, *>
            ?: error("top-level JSON is not an object")
    val groups = json["testGroups"] as? List<*> ?: error("no testGroups")

    var matchCount = 0
    var mismatchCount = 0

    for (gi in 0 until minOf(5, groups.size)) {
      val g = groups[gi] as Map<*, *>
      val privateSeed = hex(g["privateSeed"] as String)
      val expectedPk = hex(g["publicKey"] as String)
      val (pk, sk) = MLDSA44PureK.keypairFromSeed(privateSeed)

      var match = true
      for (i in pk.indices) {
        if (pk[i] != expectedPk[i]) {
          match = false
          break
        }
      }
      if (match) {
        matchCount++
      } else {
        mismatchCount++
        // Show first mismatch
        for (i in pk.indices) {
          if (pk[i] != expectedPk[i]) {
            println(
                "MLDSA44SmokeTest3: GROUP $gi MISMATCH at byte $i: got 0x${pk[i].toString(16)}, expected 0x${expectedPk[i].toString(16)}"
            )
            break
          }
        }
      }
    }

    println("MLDSA44SmokeTest3: matched=$matchCount, mismatched=$mismatchCount")
    assert(matchCount > 0) { "No keypairs matched Wycheproof expected public keys" }
    assert(mismatchCount == 0) { "$mismatchCount keypairs did not match expected values" }
  }
}

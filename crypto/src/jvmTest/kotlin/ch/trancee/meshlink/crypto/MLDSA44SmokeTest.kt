/*
 * Quick smoke test for ML-DSA-44 keypair and sign operations.
 */
package ch.trancee.meshlink.crypto

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("smoke")
class MLDSA44SmokeTest {

  @Test
  fun testKeypairFromSeed() {
    val seed = ByteArray(32) { 0x42 }
    println("MLDSA44SmokeTest: starting keypairFromSeed")
    val (pk, sk) = MLDSA44PureK.keypairFromSeed(seed)
    println("MLDSA44SmokeTest: pk size=${pk.size}, sk size=${sk.size}")
    assert(pk.size == 1312) { "pk size should be 1312, got ${pk.size}" }
    assert(sk.size == 2560) { "sk size should be 2560, got ${sk.size}" }
  }

  @Test
  fun testSignAndVerify() {
    val seed = ByteArray(32) { 0x42 }
    println("MLDSA44SmokeTest: starting keypair")
    val (pk, sk) = MLDSA44PureK.keypairFromSeed(seed)
    println("MLDSA44SmokeTest: keypair done, signing")
    val msg = "hello world".toByteArray()
    val sig = MLDSA44PureK.sign(msg, sk)
    println("MLDSA44SmokeTest: sig size=${sig.size}")
    assert(sig.size == 2420) { "sig size should be 2420, got ${sig.size}" }
    println("MLDSA44SmokeTest: verifying")
    val ok = MLDSA44PureK.verify(sig, msg, pk)
    assert(ok) { "signature should verify" }
  }

  @Test
  fun testSignFast() {
    // Test with a timeout - if it takes >30 seconds, it's probably stuck in a loop
    val seed =
        byteArrayOf(
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
            0x11,
            0x12,
            0x13,
            0x14,
            0x15,
            0x16,
            0x17,
            0x18,
            0x19,
            0x1a,
            0x1b,
            0x1c,
            0x1d,
            0x1e,
            0x1f,
        )
    println("MLDSA44SmokeTest: testSignFast - keypair")
    val (pk, sk) = MLDSA44PureK.keypairFromSeed(seed)
    println("MLDSA44SmokeTest: testSignFast - signing 10 times")
    val msg = "test".toByteArray()
    var successCount = 0
    for (i in 0 until 10) {
      println("MLDSA44SmokeTest: testSignFast - sign iteration $i")
      val sig = MLDSA44PureK.sign(msg, sk)
      println("MLDSA44SmokeTest: testSignFast - sig size=${sig.size}")
      if (sig.size == 2420 && MLDSA44PureK.verify(sig, msg, pk)) {
        successCount++
      } else {
        println("MLDSA44SmokeTest: testSignFast - FAILED at iteration $i")
      }
    }
    println("MLDSA44SmokeTest: testSignFast - success=$successCount/10")
    assert(successCount == 10) { "Expected 10/10 successes, got $successCount" }
  }
}

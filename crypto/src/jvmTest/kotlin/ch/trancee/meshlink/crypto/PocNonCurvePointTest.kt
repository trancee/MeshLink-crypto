package ch.trancee.meshlink.crypto

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Regression test: Non-curve point rejection in Ed25519 pointFromBytes.
 *
 * ref10's decode_point verifies the curve equation after the SQRTM1
 * multiplication. Points where neither x nor x*sqrt(-1) satisfies the curve
 * equation must be rejected. Without this recheck, an attacker could craft
 * points not on the curve, potentially leaking key material.
 */
internal class PocNonCurvePointTest {

  private fun pointFromBytes(yBytes: ByteArray): Boolean {
    val instance = Ed25519PureK::class.java
    val method = instance.getDeclaredMethod("pointFromBytes", ByteArray::class.java)
    method.isAccessible = true
    val singleton = instance.getField("INSTANCE").get(null)
    val result = method.invoke(singleton, yBytes)
    return result != null
  }

  @Test
  fun `pointFromBytes rejects non-curve points via SQRTM1 recheck`() {
    val p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    val d = BigInteger("-121665").multiply(BigInteger("121666").modInverse(p)).mod(p)

    // Count accepted points. Without the SQRTM1 recheck, ~100% are accepted
    // (non-curve points silently accepted). With the recheck, only valid curve
    // points pass — approximately 75% acceptance (QR u + QR u*sqrt(-1)).
    var accepted = 0
    val total = 5001
    for (yVal in 0 until total) {
      val yBytes = ByteArray(32)
      var rem = BigInteger.valueOf(yVal.toLong())
      for (i in 0 until 32) {
        yBytes[i] = (rem.and(BigInteger.valueOf(0xFF))).toByte()
        rem = rem.shiftRight(8)
      }
      if (pointFromBytes(yBytes)) accepted++
    }

    println("pointFromBytes accepted $accepted out of $total y values")
    // With the SQRTM1 recheck, non-curve points must be rejected.
    // Acceptance should be well below 100% (approximately 75%).
    assertTrue(
        accepted < total * 0.95,
        "With SQRTM1 recheck, acceptance rate must be <95%, got $accepted/$total",
    )
  }

  @Test
  fun `non-curve public key encoding is rejected by pointFromBytes`() {
    val p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    val d = BigInteger("-121665").multiply(BigInteger("121666").modInverse(p)).mod(p)

    var nonCurveY = -1L
    for (yVal in 0..5000L) {
      val y = BigInteger.valueOf(yVal)
      val y2 = y.multiply(y).mod(p)
      val u = y2.subtract(BigInteger.ONE).mod(p)
      val v = d.multiply(y2).add(BigInteger.ONE).mod(p)
      if (v == BigInteger.ZERO) continue
      val vInv = v.modInverse(p)
      val uOverV = u.multiply(vInv).mod(p)
      if (uOverV == BigInteger.ZERO) continue
      val legendre = uOverV.modPow((p.subtract(BigInteger.ONE)).shiftRight(1), p)
      if (legendre != BigInteger.ONE) {
        val negUOverV = p.subtract(uOverV)
        val legendreNeg = negUOverV.modPow((p.subtract(BigInteger.ONE)).shiftRight(1), p)
        if (legendreNeg != BigInteger.ONE) {
          nonCurveY = yVal
          break
        }
      }
    }
    assertTrue(nonCurveY > 0, "Found a non-curve y value: $nonCurveY")

    val yBytes = ByteArray(32)
    var rem = BigInteger.valueOf(nonCurveY)
    for (i in 0 until 32) {
      yBytes[i] = (rem.and(BigInteger.valueOf(0xFF))).toByte()
      rem = rem.shiftRight(8)
    }

    val accepted = pointFromBytes(yBytes)
    assertFalse(
        accepted,
        "non-curve y=$nonCurveY must be rejected by pointFromBytes (SQRTM1 recheck)",
    )
    println("CONFIRMED: non-curve y=$nonCurveY rejected — SQRTM1 recheck active in pointFromBytes")
  }
}

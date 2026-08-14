package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Regression test: X25519 all-zero shared secret (RFC 7748 §6.1).
 *
 * Low-order points (u=0, u=1, etc.) produce all-zero shared secrets that an attacker can predict.
 * Per RFC 7748 §6.1, implementations must reject the all-zero result and treat it as an error.
 */
internal class PocX25519AllZeroTest {

  @Test
  fun `PureK X25519 rejects all-zero u=0 (low-order point, RFC 7748 Section 6p1)`() {
    val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    val zeroU = ByteArray(32) { 0x00 }

    val exception =
        assertFailsWith<IllegalArgumentException> {
          X25519PureK.compute(scalar, zeroU)
        }
    assertTrue(
        exception.message?.contains("all-zero") == true,
        "PureK must reject all-zero shared secret per RFC 7748 §6.1",
    )
  }

  @Test
  fun `PureK X25519 rejects all-zero u=1 (low-order point, RFC 7748 Section 6p1)`() {
    val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    val u1 = ByteArray(32) { 0x00 }
    u1[0] = 0x01

    val exception =
        assertFailsWith<IllegalArgumentException> {
          X25519PureK.compute(scalar, u1)
        }
    assertTrue(
        exception.message?.contains("all-zero") == true,
        "PureK must reject all-zero shared secret from u=1 per RFC 7748 §6.1",
    )
  }

  @Test
  fun `Facade X25519 rejects all-zero u=0 (low-order point, RFC 7748 Section 6p1)`() {
    val scalar = PrivateKey(hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"))
    val zeroU = PublicKey(ByteArray(32) { 0x00 })

    val result = KeyExchange.x25519(scalar, zeroU)
    assertTrue(result.isFailure, "Facade must reject all-zero shared secret")
    // With narrowed x25519Native catches, JCA's InvalidKeyException is caught and
    // PureK computes the all-zero result, throwing IllegalArgumentException.
    // Both are valid rejections per RFC 7748 §6.1.
  }
}

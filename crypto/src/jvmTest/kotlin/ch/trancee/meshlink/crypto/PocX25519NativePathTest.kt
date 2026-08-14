package ch.trancee.meshlink.crypto

import java.security.InvalidKeyException
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Regression test: Confirms the facade X25519 now rejects all-zero shared secrets from low-order
 * points (u=0, u=1) regardless of which path computes the result.
 *
 * With narrowed catch blocks in x25519Native, JCA's InvalidKeyException for low-order points is
 * caught and the PureK fallback computes the result, throwing IllegalArgumentException for all-zero
 * output. If a CryptoProvider throws InvalidKeyException directly, that also propagates as a valid
 * rejection. Both are valid per RFC 7748 §6.1.
 */
internal class PocX25519NativePathTest {

  @Test
  fun `Facade rejects all-zero shared secret from u=0 after native computation`() {
    val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    val zeroU = ByteArray(32) { 0x00 }

    val result = runCatching { X25519.compute(scalar, zeroU) }
    assertTrue(
        result.isFailure,
        "X25519.compute must reject all-zero shared secret from u=0 (RFC 7748 §6.1)",
    )
    val ex = result.exceptionOrNull()
    assertTrue(
        ex is InvalidKeyException || ex is IllegalArgumentException,
        "Expected InvalidKeyException (JCA) or IllegalArgumentException (PureK), got ${ex?.javaClass}",
    )
  }

  @Test
  fun `Facade rejects all-zero shared secret from u=1 after native computation`() {
    val scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    val u1 = ByteArray(32) { 0x00 }
    u1[0] = 0x01

    val result = runCatching { X25519.compute(scalar, u1) }
    assertTrue(
        result.isFailure,
        "X25519.compute must reject all-zero shared secret from u=1 (RFC 7748 §6.1)",
    )
    val ex = result.exceptionOrNull()
    assertTrue(
        ex is InvalidKeyException || ex is IllegalArgumentException,
        "Expected InvalidKeyException (JCA) or IllegalArgumentException (PureK), got ${ex?.javaClass}",
    )
  }
}

package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Regression test: Confirms that the JCA Ed25519 path itself accepts the
 * identity-point forgery (no fix inside JCA), but that the facade now rejects
 * it via pre-dispatch identity-point check, and PureK rejects it.
 *
 * Previously the broad catch(e: Exception) { null } in ed25519VerifyNative would
 * mask JCA rejections and fall back to the vulnerable PureK path. Now the catch
 * is narrowed to NoSuchAlgorithmException, and the facade blocks identity-point
 * public keys before any native call.
 */
internal class PocJcaVsPureKEd25519Test {

  private val identityPk = byteArrayOf(0x01) + ByteArray(31) { 0x00 }
  private val zeroS = ByteArray(32) { 0x00 }
  private val forgedR = byteArrayOf(0x01) + ByteArray(31) { 0x00 }
  private val forgedSig = forgedR + zeroS
  private val msg = "any message".encodeToByteArray()

  @Test
  fun `JCA itself still accepts identity-point forgery — fix is in facade layer`() {
    // JCA does not reject identity-point public keys. The fix guards at the facade.
    val result = ed25519VerifyNative(identityPk, msg, forgedSig)
    assertTrue(
        result == true,
        "JCA itself accepts identity-point forgery — fix must guard at the facade layer",
    )
  }

  @Test
  fun `PureK verify rejects identity-point forgery (CVE-2023-38490)`() {
    assertFalse(
        Ed25519PureK.verify(identityPk, msg, forgedSig),
        "PureK must reject identity-point forgery",
    )
  }

  @Test
  fun `Facade rejects identity-point forgery — pre-dispatched before JCA`() {
    val result = Signer.ed25519Verify(PublicKey(identityPk), msg, forgedSig)
    assertFalse(
        result.getOrDefault(false),
        "Facade must reject identity-point forgery via pre-dispatch identity check",
    )
  }
}

package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertFalse

/**
 * Regression test: Identity-point public key forgery (CVE-2023-38490).
 *
 * With A = identity point (0,1), an attacker forges a valid signature with S=0
 * and R = identity encoding. verify() must now reject this.
 */
internal class PocIdentityPointForgeryTest {

  @Test
  fun `PureK verify rejects identity-point forgery (CVE-2023-38490)`() {
    val identityPublicKey = byteArrayOf(0x01) + ByteArray(31) { 0x00 }
    val zeroS = ByteArray(32) { 0x00 }
    val forgedR = byteArrayOf(0x01) + ByteArray(31) { 0x00 }
    val forgedSignature = forgedR + zeroS
    val message = "this message was never signed by anyone".encodeToByteArray()

    assertFalse(
        Ed25519PureK.verify(identityPublicKey, message, forgedSignature),
        "IDENTITY-POINT FORGERY: verify must reject forged signature with no private key",
    )
  }

  @Test
  fun `Facade verify rejects identity-point forgery via pre-dispatch check`() {
    val identityPk = byteArrayOf(0x01) + ByteArray(31) { 0x00 }
    val zeroS = ByteArray(32) { 0x00 }
    val forgedR = byteArrayOf(0x01) + ByteArray(31) { 0x00 }
    val forgedSig = forgedR + zeroS
    val msg = "any message".encodeToByteArray()
    val result = Signer.ed25519Verify(PublicKey(identityPk), msg, forgedSig)

    assertFalse(
        result.getOrDefault(false),
        "Facade must reject identity-point forgery (CVE-2023-38490)",
    )
  }
}

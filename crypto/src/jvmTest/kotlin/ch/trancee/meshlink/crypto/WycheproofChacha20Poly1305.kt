/*
 * Wycheproof ChaCha20-Poly1305 AEAD test case loader.
 *
 * The Wycheproof ChaCha20-Poly1305 schema (`chacha20_poly1305_test.json`) uses
 * `testGroups` containing `tests` arrays. Each group carries `keySize`, `ivSize`,
 * `tagSize`, `type` (always `AeadTest`), and `source` fields. Each test case
 * carries `tcId`, `comment`, `key`, `iv`, `aad`, `msg`, `ct`, `tag`, `flags`,
 * and `result`.
 *
 * Valid cases have 12-byte nonces (96-bit) and expect decryption to succeed.
 * Invalid cases use the `ModifiedTag` flag (bit-flipped tag must fail) or
 * `InvalidNonceSize` (nonce size ≠ 12 — not applicable to this library's
 * 12-byte-nonce API and filtered out at test time).
 *
 * 256 valid cases + 60 ModifiedTag cases + 9 InvalidNonceSize cases = 325 total.
 */
package ch.trancee.meshlink.crypto

internal data class WycheproofChacha20Poly1305TestCase(
    val tcId: Int,
    val comment: String,
    val key: ByteArray,
    val nonce: ByteArray,
    val aad: ByteArray,
    val plaintext: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
    val result: String,
    val flags: List<String>,
) {
  override fun equals(other: Any?): Boolean =
      other is WycheproofChacha20Poly1305TestCase &&
          tcId == other.tcId &&
          comment == other.comment &&
          key.contentEquals(other.key) &&
          nonce.contentEquals(other.nonce) &&
          aad.contentEquals(other.aad) &&
          plaintext.contentEquals(other.plaintext) &&
          ciphertext.contentEquals(other.ciphertext) &&
          tag.contentEquals(other.tag) &&
          result == other.result &&
          flags == other.flags

  override fun hashCode(): Int = tcId
}

/** Loads all test cases from a Wycheproof ChaCha20-Poly1305 JSON resource. */
internal fun loadWycheproofChacha20Poly1305(
    resourcePath: String
): List<WycheproofChacha20Poly1305TestCase> {
  val json =
      WycheproofJson.parseResource(resourcePath) as? Map<*, *>
          ?: error("top-level JSON is not an object")
  val groups = json["testGroups"] as? List<Any?> ?: emptyList()
  return groups.flatMap { group ->
    val tests = (group as Map<*, *>)["tests"] as? List<Any?> ?: emptyList()
    tests.map { testEntry ->
      val t = testEntry as Map<*, *>
      WycheproofChacha20Poly1305TestCase(
          tcId = (t["tcId"] as Number).toInt(),
          comment = t["comment"] as String,
          key = hex(t["key"] as String),
          nonce = hex(t["iv"] as String),
          aad = if ((t["aad"] as String).isEmpty()) ByteArray(0) else hex(t["aad"] as String),
          plaintext = hex(t["msg"] as String),
          ciphertext = hex(t["ct"] as String),
          tag = hex(t["tag"] as String),
          result = t["result"] as String,
          flags =
              (t["flags"] as? List<*>).let {
                it?.map { flag -> flag.toString() } ?: emptyList()
              },
      )
    }
  }
}

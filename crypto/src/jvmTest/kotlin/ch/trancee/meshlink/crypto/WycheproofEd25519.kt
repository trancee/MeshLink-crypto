/*
 * Wycheproof Ed25519 (EdDSA) test case loader.
 *
 * The Wycheproof EdDSA schema (`eddsa_test.json`) uses `testGroups` containing `tests`
 * arrays. Each group carries a `publicKey.pk` hex string (the 32-byte Ed25519 public key)
 * and a `type` field. Each test case carries `tcId`, `comment`, `msg` (hex), `sig`
 * (64-byte hex), `flags`, and `result`.
 *
 * For verification-only vectors (`EddsaVerify`), invalid cases may carry the `msg`
 * and `sig` fields but no secret key. The library's `Ed25519PureK.verify` is tested against
 * `valid` results (must accept) and `invalid` results (must reject).
 */
package ch.trancee.meshlink.crypto

internal data class WycheproofEd25519TestCase(
    val tcId: Int,
    val comment: String,
    val publicKey: ByteArray,
    val msg: ByteArray,
    val sig: ByteArray,
    val result: String,
    val flags: List<String>,
) {
  override fun equals(other: Any?): Boolean =
      other is WycheproofEd25519TestCase &&
          tcId == other.tcId &&
          comment == other.comment &&
          publicKey.contentEquals(other.publicKey) &&
          msg.contentEquals(other.msg) &&
          sig.contentEquals(other.sig) &&
          result == other.result &&
          flags == other.flags

  override fun hashCode(): Int = tcId
}

/** Loads all test cases from a Wycheproof Ed25519 JSON resource. */
internal fun loadWycheproofEd25519(resourcePath: String): List<WycheproofEd25519TestCase> {
  val json =
      WycheproofJson.parseResource(resourcePath) as? Map<*, *>
          ?: error("top-level JSON is not an object")
  val groups = json["testGroups"] as? List<Any?> ?: emptyList()
  return groups.flatMap { group ->
    val groupMap = group as Map<*, *>
    val publicKeyHex =
        ((groupMap["publicKey"] as Map<*, *>?) ?: error("group missing publicKey"))["pk"] as String
    val publicKey = hex(publicKeyHex)
    val tests = groupMap["tests"] as? List<Any?> ?: emptyList()
    tests.map { testEntry ->
      val testCase = testEntry as Map<*, *>
      WycheproofEd25519TestCase(
          tcId = (testCase["tcId"] as Number).toInt(),
          comment = testCase["comment"] as String,
          publicKey = publicKey,
          msg = hex(testCase["msg"] as String),
          sig = hex(testCase["sig"] as String),
          result = testCase["result"] as String,
          flags =
              (testCase["flags"] as? List<*>).let {
                it?.map { flag -> flag.toString() } ?: emptyList()
              },
      )
    }
  }
}

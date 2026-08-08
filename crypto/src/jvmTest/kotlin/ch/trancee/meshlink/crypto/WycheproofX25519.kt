package ch.trancee.meshlink.crypto

/**
 * Wycheproof X25519 test case loader.
 *
 * The Wycheproof X25519 schema (`xdh_comp_schema_v1.json`) uses `testGroups` containing `tests`
 * arrays with `public`, `private`, `shared`, `result`, `flags`, `tcId`, and `comment` fields.
 */
internal data class WycheproofX25519TestCase(
    val tcId: Int,
    val comment: String,
    val public: ByteArray,
    val private: ByteArray,
    val shared: ByteArray,
    val result: String,
    val flags: List<String>,
) {
  override fun equals(other: Any?): Boolean =
      other is WycheproofX25519TestCase &&
          tcId == other.tcId &&
          comment == other.comment &&
          public.contentEquals(other.public) &&
          private.contentEquals(other.private) &&
          shared.contentEquals(other.shared) &&
          result == other.result &&
          flags == other.flags

  override fun hashCode(): Int = tcId
}

/** Loads all test cases from a Wycheproof X25519 JSON resource. */
internal fun loadWycheproofX25519(resourcePath: String): List<WycheproofX25519TestCase> {
  val json =
      WycheproofJson.parseResource(resourcePath) as? Map<*, *>
          ?: error("top-level JSON is not an object")
  val groups = json["testGroups"] as? List<Any?> ?: emptyList()
  return groups.flatMap { group ->
    val groupMap = group as Map<*, *>
    val tests = groupMap["tests"] as? List<Any?> ?: emptyList()
    tests.map { testEntry ->
      val testCase = testEntry as Map<*, *>
      WycheproofX25519TestCase(
          tcId = (testCase["tcId"] as Number).toInt(),
          comment = testCase["comment"] as String,
          public = hex(testCase["public"] as String),
          private = hex(testCase["private"] as String),
          shared = hex(testCase["shared"] as String),
          result = testCase["result"] as String,
          flags =
              (testCase["flags"] as? List<*>).let {
                it?.map { flag -> flag.toString() } ?: emptyList()
              },
      )
    }
  }
}

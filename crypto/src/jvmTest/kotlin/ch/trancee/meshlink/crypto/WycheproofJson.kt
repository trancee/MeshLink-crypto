package ch.trancee.meshlink.crypto

/**
 * Minimal self-contained JSON parser for loading Wycheproof test vector resources.
 *
 * Parses a JSON document into Kotlin [Map]/[List]/[String]/[Number]/[Boolean]/[null] values so test
 * code can traverse the Wycheproof `MacTest` schema without a third-party dependency (the library
 * ships zero runtime deps; test-only JSON parsing is kept dependency-free too, per ADR-0003 /
 * ADR-0007).
 *
 * The parser is strict enough for the Wycheproof schema (nested objects, arrays, strings, integers)
 * and rejects genuinely malformed input. It is not a general-purpose RFC 8259 parser — only the
 * constructs used by Wycheproof test vectors are supported.
 */
internal object WycheproofJson {

  /** Parses a JSON string into Kotlin values. */
  fun parse(input: String): Any? = Parser(input).parse()

  /** Reads a resource from the classpath and parses it as JSON. */
  fun parseResource(path: String): Any? = parse(loadResourceText(path))

  // ---------------------------------------------------------------------------
  // Compact recursive-descent parser
  // ---------------------------------------------------------------------------

  private class Parser(private val input: String) {
    private var position = 0

    fun parse(): Any? {
      skipWhitespace()
      return parseValue()
    }

    fun parseValue(): Any? {
      skipWhitespace()
      check(position < input.length) { "unexpected end of input" }
      val char = input[position]
      return when (char) {
        '{' -> parseObject()
        '[' -> parseArray()
        '"' -> parseString()
        't' -> parseLiteral("true", true)
        'f' -> parseLiteral("false", false)
        'n' -> parseLiteral("null", null)
        else -> parseNumber()
      }
    }

    private fun parseObject(): Map<String, Any?> {
      position++ // consume '{'
      skipWhitespace()
      val map = LinkedHashMap<String, Any?>()
      if (position < input.length && input[position] == '}') {
        position++
        return map
      }
      while (true) {
        skipWhitespace()
        val key = parseString()
        skipWhitespace()
        check(input[position] == ':') { "expected ':' after key \"$key\"" }
        position++ // consume ':'
        map[key] = parseValue()
        skipWhitespace()
        when (input[position]) {
          ',' -> position++
          '}' -> {
            position++
            return map
          }
          else -> error("expected ',' or '}' in object")
        }
      }
    }

    private fun parseArray(): List<Any?> {
      position++ // consume '['
      skipWhitespace()
      val list = mutableListOf<Any?>()
      if (position < input.length && input[position] == ']') {
        position++
        return list
      }
      while (true) {
        list.add(parseValue())
        skipWhitespace()
        when (input[position]) {
          ',' -> position++
          ']' -> {
            position++
            return list
          }
          else -> error("expected ',' or ']' in array")
        }
      }
    }

    private fun parseString(): String {
      check(input[position] == '"') { "expected string" }
      position++ // consume opening '"'
      val builder = StringBuilder()
      while (position < input.length) {
        val char = input[position]
        if (char == '"') {
          position++
          return builder.toString()
        }
        if (char == '\\') {
          position++
          check(position < input.length) { "unterminated escape" }
          builder.append(
              when (input[position]) {
                '"' -> '"'
                '\\' -> '\\'
                '/' -> '/'
                'n' -> '\n'
                't' -> '\t'
                'r' -> '\r'
                'b' -> '\b'
                'f' -> '\u000C'
                'u' -> {
                  val hexValue = input.substring(position + 1, position + 5)
                  position += 4
                  hexValue.toInt(16).toChar()
                }
                else -> error("invalid escape: \\${input[position]}")
              },
          )
          position++
        } else {
          builder.append(char)
          position++
        }
      }
      error("unterminated string")
    }

    private fun parseNumber(): Number {
      val start = position
      while (
          position < input.length && (input[position].isDigit() || input[position] in "+-.eE")
      ) position++
      val source = input.substring(start, position)
      return if (source.contains('.') || source.contains('e') || source.contains('E'))
          source.toDouble()
      else source.toLong()
    }

    private fun <T> parseLiteral(expected: String, value: T): T {
      check(input.substring(position, position + expected.length) == expected) {
        "expected '$expected'"
      }
      position += expected.length
      return value
    }

    private fun skipWhitespace() {
      while (position < input.length && input[position] in " \t\n\r") position++
    }

    private fun check(condition: Boolean, message: () -> Any) {
      if (!condition) error(message().toString())
    }
  }
}

/** A single Wycheproof HMAC-SHA256 test case. */
internal data class WycheproofTestCase(
    val tcId: Int,
    val key: ByteArray,
    val msg: ByteArray,
    val tag: ByteArray,
    val result: String,
    val flags: List<String>,
) {
  override fun equals(other: Any?): Boolean =
      other is WycheproofTestCase &&
          tcId == other.tcId &&
          key.contentEquals(other.key) &&
          msg.contentEquals(other.msg) &&
          tag.contentEquals(other.tag) &&
          result == other.result

  override fun hashCode(): Int = tcId
}

/** Loads all test cases from a Wycheproof MacTest JSON resource. */
internal fun loadWycheproof(resourcePath: String): List<WycheproofTestCase> {
  val json =
      WycheproofJson.parseResource(resourcePath) as? Map<*, *>
          ?: error("top-level JSON is not an object")
  val groups = json["testGroups"] as? List<Any?> ?: emptyList()
  return groups.flatMap { group ->
    val groupMap = group as Map<*, *>
    val tests = groupMap["tests"] as? List<Any?> ?: emptyList()
    tests.map { testEntry ->
      val testCase = testEntry as Map<*, *>
      WycheproofTestCase(
          tcId = (testCase["tcId"] as Number).toInt(),
          key = hex(testCase["key"] as String),
          msg = hex(testCase["msg"] as String),
          tag = hex(testCase["tag"] as String),
          result = testCase["result"] as String,
          flags =
              (testCase["flags"] as? List<*>).let {
                it?.map { flag -> flag.toString() } ?: emptyList()
              },
      )
    }
  }
}

/** A single Wycheproof HKDF-SHA256 test case. */
internal data class WycheproofHkdfTestCase(
    val tcId: Int,
    val ikm: ByteArray,
    val salt: ByteArray,
    val info: ByteArray,
    val outputLength: Int,
    val okm: ByteArray,
    val result: String,
    val flags: List<String>,
) {
  override fun equals(other: Any?): Boolean =
      other is WycheproofHkdfTestCase &&
          tcId == other.tcId &&
          ikm.contentEquals(other.ikm) &&
          salt.contentEquals(other.salt) &&
          info.contentEquals(other.info) &&
          outputLength == other.outputLength &&
          okm.contentEquals(other.okm) &&
          result == other.result

  override fun hashCode(): Int = tcId
}

/** Loads all test cases from a Wycheproof HkdfTest JSON resource. */
internal fun loadWycheproofHkdf(resourcePath: String): List<WycheproofHkdfTestCase> {
  val json =
      WycheproofJson.parseResource(resourcePath) as? Map<*, *>
          ?: error("top-level JSON is not an object")
  val groups = json["testGroups"] as? List<Any?> ?: emptyList()
  return groups.flatMap { group ->
    val groupMap = group as Map<*, *>
    val tests = groupMap["tests"] as? List<Any?> ?: emptyList()
    tests.map { testEntry ->
      val testCase = testEntry as Map<*, *>
      WycheproofHkdfTestCase(
          tcId = (testCase["tcId"] as Number).toInt(),
          ikm = hex(testCase["ikm"] as String),
          salt = hex(testCase["salt"] as String),
          info = hex(testCase["info"] as String),
          outputLength = (testCase["size"] as Number).toInt(),
          okm = hex(testCase["okm"] as String),
          result = testCase["result"] as String,
          flags =
              (testCase["flags"] as? List<*>).let {
                it?.map { flag -> flag.toString() } ?: emptyList()
              },
      )
    }
  }
}

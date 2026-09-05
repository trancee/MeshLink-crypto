package ch.trancee.meshlink.crypto

/**
 * NIST KAT .rsp format parser for Falcon-512 test vectors.
 *
 * Methodology follows the libacvp-json-kotlin skill adapted for the .rsp format (line-based, not
 * JSON):
 * 1. Shape-first classification: NIST KAT .rsp (# comments, blank-line separators, `name = value`
 *    fields)
 * 2. Strict field validation: required field names, integer parsing
 * 3. Typed model: [FalconKatVector] with validated [ByteArray] fields
 * 4. Hex validation: ASCII-hex check, even length, exact byte width
 *
 * Reference: NIST PQC Round 3 Falcon-512 KAT (falcon512-KAT.rsp). Field sizes (from
 * PQCLEAN_FALCON512_CLEAN_API_H):
 * - seed: 48 bytes (NIST KAT seed)
 * - pk: 897 bytes (PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES)
 * - sk: 1281 bytes (PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES)
 * - msg: mlen bytes (variable, read from `mlen` field)
 * - sm: smlen bytes (variable, read from `smlen` field)
 *
 * NOTE: `FALCON_KAT_FIELDS` matches the order fields appear in the .rsp file (count, seed, mlen,
 * msg, pk, sk, smlen, sm), which differs from the listing in
 * docs/research/wayfinder-66/falcon-landscape.md:244 (count, seed, pk, sk, sm, msg, smlen, mlen).
 * Order is parser-irrelevant — fields are collected into a LinkedHashMap and validated by set
 * membership.
 */
internal const val FALCON512_SEED_BYTES = 48
internal const val FALCON512_PK_BYTES = 897
internal const val FALCON512_SK_BYTES = 1281

/** Canonical field names in the KAT .rsp format. */
internal val FALCON_KAT_FIELDS: List<String> =
    listOf("count", "seed", "mlen", "msg", "pk", "sk", "smlen", "sm")

/** A single Falcon-512 KAT vector parsed from the .rsp file. */
internal data class FalconKatVector(
    val count: Long,
    val seed: ByteArray,
    val mlen: Long,
    val msg: ByteArray,
    val pk: ByteArray,
    val sk: ByteArray,
    val smlen: Long,
    val sm: ByteArray,
) {
  override fun equals(other: Any?): Boolean =
      other is FalconKatVector &&
          count == other.count &&
          seed.contentEquals(other.seed) &&
          mlen == other.mlen &&
          msg.contentEquals(other.msg) &&
          pk.contentEquals(other.pk) &&
          sk.contentEquals(other.sk) &&
          smlen == other.smlen &&
          sm.contentEquals(other.sm)

  // hashCode uses only `count` — consistent with WycheproofTestCase pattern.
  // ByteArray contentHashCode is intentionally omitted for performance (pk=897B, sk=1281B).
  override fun hashCode(): Int = count.hashCode()
}

/**
 * Validates and converts a hex string to [ByteArray].
 *
 * Delegates ASCII-hex validation and even-length checking to [hex], which already enforces both.
 * This function adds: null/empty handling (via [allowEmpty]), and optional exact byte-width
 * validation.
 *
 * @param value the raw hex string from the .rsp file (or null if field missing)
 * @param name field name for error messages
 * @param expectedBytes required byte width, or null to skip width check
 * @param allowEmpty if true, null/empty value returns [ByteArray] of size 0
 * @return validated [ByteArray]
 */
internal fun requireHex(
    value: String?,
    name: String,
    expectedBytes: Int? = null,
    allowEmpty: Boolean = false,
): ByteArray {
  if (value == null || value.isEmpty()) {
    require(allowEmpty) { "$name must not be empty (field missing or blank)" }
    return ByteArray(0)
  }
  val bytes = hex(value)
  if (expectedBytes != null) {
    require(bytes.size == expectedBytes) {
      "$name must be $expectedBytes bytes, got ${bytes.size}"
    }
  }
  return bytes
}

/** Parses NIST KAT .rsp text into a list of [FalconKatVector]. */
internal object FalconKatParser {

  fun parseRsp(text: String): List<FalconKatVector> {
    val lines = text.lines()
    var idx = 0
    val vectors = mutableListOf<FalconKatVector>()

    while (idx < lines.size) {
      idx = skipCommentsAndBlanks(lines, idx)
      if (idx >= lines.size) break

      val (fields, nextIdx) = readVectorBlock(lines, idx)
      if (fields.isEmpty()) break

      // Strict validation: reject unknown fields
      fields.keys.forEach { name ->
        require(name in FALCON_KAT_FIELDS) { "Unknown field '$name' in KAT vector" }
      }
      // Strict validation: reject missing required fields
      val missing = FALCON_KAT_FIELDS - fields.keys
      require(missing.isEmpty()) {
        "Missing required field(s): $missing in KAT vector"
      }

      vectors.add(parseVector(fields))
      idx = nextIdx
    }

    return vectors
  }

  private fun skipCommentsAndBlanks(lines: List<String>, idx: Int): Int {
    var i = idx
    while (i < lines.size) {
      if (isJunk(lines[i])) {
        i++
        continue
      }
      return i // First content line found
    }
    return i
  }

  private fun readVectorBlock(
      lines: List<String>,
      start: Int,
  ): Pair<Map<String, String>, Int> {
    val fields = LinkedHashMap<String, String>()
    var i = start
    while (i < lines.size) {
      val trimmed = lines[i].trim()
      if (isJunk(lines[i])) break
      val eqIdx = trimmed.indexOf('=')
      require(eqIdx >= 0) { "Malformed KAT line (no '='): ${trimmed.take(20)}" }
      val name = trimmed.substring(0, eqIdx).trim()
      val value = trimmed.substring(eqIdx + 1).trim()
      require(name !in fields) { "Duplicate field '$name' in KAT vector" }
      fields[name] = value
      i++
    }
    return Pair(fields, i)
  }

  private fun parseVector(fields: Map<String, String>): FalconKatVector {
    val count =
        fields["count"]?.toLongOrNull() ?: error("Invalid 'count' field: ${fields["count"]}")
    val seed = requireHex(fields["seed"], "seed", expectedBytes = FALCON512_SEED_BYTES)
    val mlen = fields["mlen"]?.toLongOrNull() ?: error("Invalid 'mlen' field: ${fields["mlen"]}")
    val msg =
        requireHex(
            fields["msg"],
            "msg",
            expectedBytes = mlen.toInt(),
            allowEmpty = mlen == 0L,
        )
    val pk = requireHex(fields["pk"], "pk", expectedBytes = FALCON512_PK_BYTES)
    val sk = requireHex(fields["sk"], "sk", expectedBytes = FALCON512_SK_BYTES)
    val smlen =
        fields["smlen"]?.toLongOrNull() ?: error("Invalid 'smlen' field: ${fields["smlen"]}")
    val sm =
        requireHex(
            fields["sm"],
            "sm",
            expectedBytes = smlen.toInt(),
            allowEmpty = smlen == 0L,
        )
    return FalconKatVector(count, seed, mlen, msg, pk, sk, smlen, sm)
  }
}

/**
 * Returns true for blank lines and `#` comments in KAT .rsp text. Shared by
 * [FalconKatParser.skipCommentsAndBlanks] and [FalconKatParser.readVectorBlock].
 */
private fun isJunk(line: String): Boolean {
  val trimmed = line.trim()
  return trimmed.isEmpty() || trimmed.startsWith("#")
}

/** Loads all 100 Falcon-512 KAT vectors from the classpath resource. */
internal fun loadFalconKat512Vectors(): List<FalconKatVector> {
  val text = loadResourceText("/falcon/falcon512-KAT.rsp")
  return FalconKatParser.parseRsp(text)
}

package ch.trancee.meshlink.crypto

/**
 * HMAC-SHA256 (RFC 2104). Pure-Kotlin, constant-time, built on ticket 03's SHA-256.
 *
 * Internal — consumed by HKDF (ticket 06) and the public facade (ticket 12).
 *
 * The construction is `HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))` where:
 * - `H` is SHA-256 (block size B = 64, output L = 32).
 * - `ipad` = 0x36 repeated B times, `opad` = 0x5c repeated B times.
 * - If `len(K) > B`, K is first hashed to L bytes (RFC 2104 §3).
 *
 * Constant-time discipline (ADR-0003):
 * - Key length is public metadata, not secret content. The length check `byteCount > BLOCK_SIZE`
 *   branches on `byteCount` — a local derived from `key.size` — never on a `@Secret` parameter
 *   name, so the detekt `ConstantTimeRule` does not flag it.
 * - The key XOR loop runs a fixed `BLOCK_SIZE` iterations with no data-dependent branch and a
 *   non-secret index.
 * - `SHA256Hasher` compression is fixed-round, no data-dependent indexing.
 * - `verify` compares every byte unconditionally (no early exit) via a bitwise-OR accumulator, so a
 *   mismatched byte never short-circuits.
 */
internal object HMAC_SHA256 {

  /** SHA-256 block size in bytes (RFC 6234 §5.1). */
  private const val BLOCK_SIZE = 64

  /** Inner pad byte (RFC 2104 §2). */
  private const val IPAD = 0x36

  /** Outer pad byte (RFC 2104 §2). */
  private const val OPAD = 0x5c

  /**
   * Computes HMAC-SHA256 over [message] using [key].
   *
   * @param key the secret authentication key (any length; ≤64 B used directly, >64 B is first
   *   SHA-256-hashed per RFC 2104 §3).
   * @param message the message to authenticate.
   * @return 32-byte HMAC-SHA256 tag (big-endian, RFC 2104 §2).
   */
  fun digest(@Secret key: ByteArray, @Secret message: ByteArray): ByteArray {
    // Key normalization — key length is public, not secret content.
    val byteCount = key.size
    val normalizedKey = if (byteCount > BLOCK_SIZE) SHA256.digest(key) else key

    // Build K ⊕ ipad and K ⊕ opad, zero-padded to block size.
    // Initialise every byte with the pad constant (0x36 / 0x5c); zero-padded
    // key bytes XOR with 0x36/0x5c → the pad constant itself.
    val innerPad = ByteArray(BLOCK_SIZE) { IPAD.toByte() }
    val outerPad = ByteArray(BLOCK_SIZE) { OPAD.toByte() }
    val copyLength = minOf(normalizedKey.size, BLOCK_SIZE)
    for (index in 0 until copyLength) {
      val byte = normalizedKey[index].toInt() and 0xFF
      innerPad[index] = (IPAD xor byte).toByte()
      outerPad[index] = (OPAD xor byte).toByte()
    }

    // Inner hash: H(K ⊕ ipad || message)
    val innerHasher = SHA256Hasher()
    innerHasher.update(innerPad, 0, innerPad.size)
    innerHasher.update(message, 0, message.size)
    val innerDigest = innerHasher.digest()

    // Outer hash: H(K ⊕ opad || innerHash)
    val outerHasher = SHA256Hasher()
    outerHasher.update(outerPad, 0, outerPad.size)
    outerHasher.update(innerDigest, 0, innerDigest.size)
    return outerHasher.digest()
  }

  /**
   * Verifies [tag] against `HMAC-SHA256(key, message)` in constant time.
   *
   * @param key the secret authentication key.
   * @param message the authenticated message.
   * @param tag the candidate tag (any length).
   * @return `true` only if [tag] exactly matches the computed 32-byte tag.
   */
  fun verify(@Secret key: ByteArray, @Secret message: ByteArray, @Secret tag: ByteArray): Boolean {
    val computed = digest(key, message)
    var difference = computed.size xor tag.size
    val compareLength = minOf(computed.size, tag.size)
    for (index in 0 until compareLength) {
      difference = difference or (computed[index].toInt() xor tag[index].toInt())
    }
    return difference == 0
  }
}

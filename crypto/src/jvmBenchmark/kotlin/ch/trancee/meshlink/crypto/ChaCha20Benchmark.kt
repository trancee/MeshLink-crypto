/*
 * JMH microbenchmark for ChaCha20-Poly1305 AEAD (ADR-0009).
 *
 * Measures encrypt and decrypt throughput at ChaCha20 keystream-block
 * boundaries (block = 64 bytes): empty, small, one-block, two-block, large (1 MiB).
 * Pre-computed ciphertexts let the decrypt benchmarks isolate decryption cost.
 *
 * The encrypt benchmark includes nonce generation (SecureRandom), giving the
 * true end-to-end cost a caller pays.
 */
package ch.trancee.meshlink.crypto

import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Benchmark)
class ChaCha20Benchmark {

  // Key from RFC 8439 §2.8 test vector.
  private lateinit var katKey: ByteArray

  // Message sizes spanning ChaCha20 keystream-block boundaries (block = 64 bytes).
  private lateinit var emptyMessage: ByteArray
  private lateinit var smallMessage: ByteArray
  private lateinit var oneBlockMessage: ByteArray
  private lateinit var twoBlockMessage: ByteArray
  private lateinit var largeMessage: ByteArray

  // Pre-computed ciphertexts for decrypt benchmarks.
  private lateinit var emptyCt: ByteArray
  private lateinit var smallCt: ByteArray
  private lateinit var oneBlockCt: ByteArray
  private lateinit var twoBlockCt: ByteArray
  private lateinit var largeCt: ByteArray

  @Setup
  fun setup() {
    katKey = hexBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")

    emptyMessage = ByteArray(0)
    smallMessage = "abc".encodeToByteArray()
    oneBlockMessage = ByteArray(48) { 0x61 } // < 1 block
    twoBlockMessage = ByteArray(128) { 0x42 } // exactly 2 blocks
    largeMessage = ByteArray(1_048_576) { 0x43 } // 1 MiB

    emptyCt = ChaCha20Poly1305PureK.encrypt(katKey, emptyMessage)
    smallCt = ChaCha20Poly1305PureK.encrypt(katKey, smallMessage)
    oneBlockCt = ChaCha20Poly1305PureK.encrypt(katKey, oneBlockMessage)
    twoBlockCt = ChaCha20Poly1305PureK.encrypt(katKey, twoBlockMessage)
    largeCt = ChaCha20Poly1305PureK.encrypt(katKey, largeMessage)
  }

  // ------------------------------------------------------------------
  // Encryption (includes SecureRandom nonce generation)
  // ------------------------------------------------------------------

  @Benchmark fun encryptEmpty(): ByteArray = ChaCha20Poly1305PureK.encrypt(katKey, emptyMessage)

  @Benchmark fun encryptSmall(): ByteArray = ChaCha20Poly1305PureK.encrypt(katKey, smallMessage)

  @Benchmark
  fun encryptOneBlock(): ByteArray = ChaCha20Poly1305PureK.encrypt(katKey, oneBlockMessage)

  @Benchmark
  fun encryptTwoBlocks(): ByteArray = ChaCha20Poly1305PureK.encrypt(katKey, twoBlockMessage)

  @Benchmark fun encryptLarge(): ByteArray = ChaCha20Poly1305PureK.encrypt(katKey, largeMessage)

  // ------------------------------------------------------------------
  // Decryption (pre-computed ciphertext, isolates decrypt cost)
  // ------------------------------------------------------------------

  @Benchmark fun decryptEmpty(): ByteArray? = ChaCha20Poly1305PureK.decrypt(katKey, emptyCt)

  @Benchmark fun decryptSmall(): ByteArray? = ChaCha20Poly1305PureK.decrypt(katKey, smallCt)

  @Benchmark fun decryptOneBlock(): ByteArray? = ChaCha20Poly1305PureK.decrypt(katKey, oneBlockCt)

  @Benchmark fun decryptTwoBlocks(): ByteArray? = ChaCha20Poly1305PureK.decrypt(katKey, twoBlockCt)

  @Benchmark fun decryptLarge(): ByteArray? = ChaCha20Poly1305PureK.decrypt(katKey, largeCt)

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  private fun hexBytes(s: String): ByteArray =
      ByteArray(s.length / 2) { i ->
        val hi = s[i * 2].digitToInt(16)
        val lo = s[i * 2 + 1].digitToInt(16)
        (hi shl 4 or lo).toByte()
      }
}

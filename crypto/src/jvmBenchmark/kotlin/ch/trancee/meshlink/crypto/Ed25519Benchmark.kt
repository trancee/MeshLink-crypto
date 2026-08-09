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
class Ed25519Benchmark {

  // Pre-generated inputs. Secret keys from RFC 8032 §7.1 KAT vectors.
  // Message sizes span SHA-512's block boundaries (block = 128 bytes):
  //   empty, small, one-block (111 bytes fits before padding spill),
  //   two-block (256 bytes), large (1 MiB).
  // Signatures are pre-computed in [setup] so verify benchmarks measure
  // only verification, not signing cost.

  private lateinit var katSecretKey1: ByteArray
  private lateinit var katSecretKey2: ByteArray
  private lateinit var katPublicKey1: ByteArray

  // Edge-case secret keys
  private lateinit var allZeroSecretKey: ByteArray
  private lateinit var allOnesSecretKey: ByteArray

  // Message sizes at SHA-512 block-size boundaries
  private lateinit var emptyMessage: ByteArray
  private lateinit var smallMessage: ByteArray
  private lateinit var oneBlockMessage: ByteArray
  private lateinit var twoBlockMessage: ByteArray
  private lateinit var largeMessage: ByteArray

  // Pre-computed signatures for verify benchmarks
  private lateinit var sigEmpty: ByteArray
  private lateinit var sigSmall: ByteArray
  private lateinit var sigOneBlock: ByteArray
  private lateinit var sigTwoBlocks: ByteArray
  private lateinit var sigLarge: ByteArray

  // Tampered signature (R bit flipped) for invalid-verify benchmark
  private lateinit var tamperedSig: ByteArray

  @Setup
  fun setup() {
    katSecretKey1 = hexBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    katPublicKey1 = hexBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    katSecretKey2 = hexBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    allZeroSecretKey = ByteArray(32)
    allOnesSecretKey = ByteArray(32) { 0xFF.toByte() }

    emptyMessage = ByteArray(0)
    smallMessage = "abc".encodeToByteArray()
    oneBlockMessage = ByteArray(111) { 0x61 }
    twoBlockMessage = ByteArray(256) { (it % 251).toByte() }
    largeMessage = ByteArray(1_048_576) { 0x61 }

    sigEmpty = Ed25519.sign(katSecretKey1, emptyMessage)
    sigSmall = Ed25519.sign(katSecretKey1, smallMessage)
    sigOneBlock = Ed25519.sign(katSecretKey1, oneBlockMessage)
    sigTwoBlocks = Ed25519.sign(katSecretKey1, twoBlockMessage)
    sigLarge = Ed25519.sign(katSecretKey1, largeMessage)

    tamperedSig = sigEmpty.copyOf()
    tamperedSig[0] = (tamperedSig[0].toInt() xor 1).toByte()
  }

  // ------------------------------------------------------------------
  // Public key derivation (publicKeyFromPrivate)
  //
  // Benchmarks the one-shot scalar multiplication at the Ed25519 base
  // point. KAT vectors verify correctness; all-zero / all-ones exercise
  // carry-propagation edge cases (ADR-0001).
  // ------------------------------------------------------------------

  @Benchmark fun keyDerivationKat1(): ByteArray = Ed25519.publicKeyFromPrivate(katSecretKey1)

  @Benchmark fun keyDerivationKat2(): ByteArray = Ed25519.publicKeyFromPrivate(katSecretKey2)

  @Benchmark fun keyDerivationAllZero(): ByteArray = Ed25519.publicKeyFromPrivate(allZeroSecretKey)

  @Benchmark fun keyDerivationAllOnes(): ByteArray = Ed25519.publicKeyFromPrivate(allOnesSecretKey)

  // ------------------------------------------------------------------
  // Signing (sign) at SHA-512 block-size boundaries
  // ------------------------------------------------------------------

  @Benchmark fun signEmpty(): ByteArray = Ed25519.sign(katSecretKey1, emptyMessage)

  @Benchmark fun signSmall(): ByteArray = Ed25519.sign(katSecretKey1, smallMessage)

  @Benchmark fun signOneBlock(): ByteArray = Ed25519.sign(katSecretKey1, oneBlockMessage)

  @Benchmark fun signTwoBlocks(): ByteArray = Ed25519.sign(katSecretKey1, twoBlockMessage)

  @Benchmark fun signLarge(): ByteArray = Ed25519.sign(katSecretKey1, largeMessage)

  // ------------------------------------------------------------------
  // Verification (verify) at SHA-512 block-size boundaries
  // ------------------------------------------------------------------

  @Benchmark fun verifyValidEmpty(): Boolean = Ed25519.verify(katPublicKey1, emptyMessage, sigEmpty)

  @Benchmark fun verifyValidSmall(): Boolean = Ed25519.verify(katPublicKey1, smallMessage, sigSmall)

  @Benchmark
  fun verifyValidOneBlock(): Boolean = Ed25519.verify(katPublicKey1, oneBlockMessage, sigOneBlock)

  @Benchmark
  fun verifyValidTwoBlocks(): Boolean = Ed25519.verify(katPublicKey1, twoBlockMessage, sigTwoBlocks)

  @Benchmark fun verifyValidLarge(): Boolean = Ed25519.verify(katPublicKey1, largeMessage, sigLarge)

  // ------------------------------------------------------------------
  // Rejection paths (verify returns false without throwing)
  // ------------------------------------------------------------------

  @Benchmark
  fun verifyTamperedR(): Boolean = Ed25519.verify(katPublicKey1, emptyMessage, tamperedSig)

  @Benchmark
  fun verifyWrongMessage(): Boolean = Ed25519.verify(katPublicKey1, smallMessage, sigEmpty)

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

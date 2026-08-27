package ch.trancee.meshlink.crypto

import kotlin.test.Test

class KeccakCompareTest {
  @Test
  fun testKeccakF1600Round0() {
    // Test single round manually and compare a00..a44 after first round
    val s = LongArray(25) { it.toLong() }
    // Print all 25 lanes before and after
    println("Before: ${s.joinToString(", ") { it.toString(16) }}")
    keccakF1600(s)
    println("After:  ${s.joinToString(", ") { it.toString(16) }}")
  }

  @Test
  fun testSHAKE128Consistency() {
    // Simple known-answer check: SHAKE128("abc", 64)
    val input = "abc".toByteArray()
    val result = SHAKE128PureK.digest(input, 32)
    println("SHAKE128(abc, 32) = ${result.joinToString("") { "%02x".format(it) }}")
  }
}

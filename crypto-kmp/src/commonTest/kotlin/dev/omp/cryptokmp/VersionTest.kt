package dev.omp.cryptokmp

import kotlin.test.Test
import kotlin.test.assertEquals

internal class VersionTest {
  @Test
  fun `module version matches the published contract`() {
    assertEquals("0.1.0-SNAPSHOT", moduleVersion())
  }
}

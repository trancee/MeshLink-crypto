package ch.trancee.meshlink.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import org.junit.jupiter.api.Tag

internal class VersionTest {
  @Tag("positive")
  @Tag("smoke")
  @Test
  fun `module version matches the published contract`() {
    assertEquals("0.1.0-SNAPSHOT", moduleVersion())
  }
}

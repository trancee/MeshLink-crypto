// Plugins are declared `apply false` at the root so each Kotlin/AGP/detekt plugin is
// resolved once and shared by the subprojects. Without this, every Kotlin-based
// subproject applies the Kotlin Gradle plugin via the `plugins {}` DSL and Gradle warns
// that the Kotlin plugin was "loaded multiple times" (e.g. :crypto + :crypto-detekt-rules).
// Each subproject still applies only the plugins it needs via the version catalog.
// (ADR-0007 / ticket 01 / ticket 02.)
plugins {
  alias(libs.plugins.kotlinMultiplatform) apply false
  alias(libs.plugins.kotlinJvm) apply false
  alias(libs.plugins.androidLibrary) apply false
  alias(libs.plugins.detekt) apply false
  alias(libs.plugins.kover) apply false
  alias(libs.plugins.spotless) apply false
  alias(libs.plugins.dokka) apply false
}

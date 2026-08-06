// Host-only JVM subproject that ships the custom detekt rule set enforcing
// constant-time discipline over the pure-K `common` sources of `:crypto`.
// It carries zero runtime dependencies for the shipped library (ADR-0005); the
// detekt API is `compileOnly` (provided by the detekt Gradle plugin at mdk time)
// and the rule's ServiceLoader is picked up by the `detektPlugins` configuration
// wired into `:crypto`. (ADR-0007 / ticket 02.)
plugins {
  alias(libs.plugins.kotlinJvm)
}

kotlin {
  jvmToolchain(21)
}

dependencies {
  compileOnly(libs.detekt.api)
  testImplementation(libs.detekt.test)
  testImplementation(kotlin("test"))
}

@file:OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)

import org.gradle.api.publish.maven.MavenPublication

plugins {
  alias(libs.plugins.kotlinMultiplatform)
  alias(libs.plugins.androidLibrary)
  alias(libs.plugins.detekt)
  alias(libs.plugins.kover)
  alias(libs.plugins.spotless)
  alias(libs.plugins.dokka)
  id("maven-publish")
  id("signing")
}

group = "ch.trancee.meshlink"

// Version comes from the version catalog (libs.versions TOML); not hardcoded.
version = libs.versions.library.get()

kotlin {
  jvm()
  // android config lives INSIDE `kotlin { android { } }` (there is no top-level
  // `android {}` extension). See:
  // https://developer.android.com/kotlin/multiplatform/plugin
  android {
    namespace = "ch.trancee.meshlink.crypto"
    // compileSdk is overridable via -PcompileSdkOverride=<api> for CI matrix
    // testing across Android API levels (ADR-0007). Default: 37 (latest stable).
    compileSdk = (findProperty("compileSdkOverride") as? String)?.toIntOrNull() ?: 37
    minSdk = 21
    // targetSdk omitted: library module — AGP 9.x deprecated targetSdk in a
    // library default config; the consuming app sets the rollout target (ADR-0007).
  }

  iosArm64()
  iosSimulatorArm64()

  sourceSets {
    getByName("commonTest") {
      dependencies {
        implementation(kotlin("test"))
      }
    }
  }

  // Binary compatibility validation via the KGP built-in ABI dumper (ADR-0007).
  compilerOptions {
    freeCompilerArgs = listOf("-Xexpect-actual-classes")
  }
  abiValidation {}
}

// iOS (native) tests require a running simulator/device to execute. On macOS we enable
// the arm64 iOS simulator test (iosSimulatorArm64Test) to validate native dispatch
// interop (ADR-0002) via InteropHarnessTest (commonTest, which uses kotlin.test —
// multiplatform, no JUnit 5 tags needed). On non-macOS hosts all iOS tests are disabled
// so `:check` is green for local development.
// iOS binaries still compile (metadata + KLib) and feed the abiValidation gate;
// the pure-K path is covered by the JVM suite + kover. (ADR-0007 / ticket 01.)
tasks
    .matching {
      it.name.startsWith("ios") && it.name.endsWith("Test")
    }
    .configureEach {
      val isMacOs = System.getProperty("os.name").lowercase().contains("mac")
      enabled = isMacOs && name == "iosSimulatorArm64Test"
    }

// JUnit 5 trait-tag filter (ADR-0003, seam 3). Tests carry @Tag annotations.
tasks.named<org.gradle.api.tasks.testing.Test>("jvmTest") {
  useJUnitPlatform {
    // includeTags("positive", "critical-path")
    // includeTags("timing")  // opt-in: timing variance assertions (ADR-0003 §4)
  }
}

// detekt (ADR-0007): 2.0's top-level `detekt` task is a no-source aggregator; the
// per-source-set `detekt*SourceSet` / `detektMainAndroid` / `detektTestJvm` tasks
// are the real linters. Wire `check` to them so static analysis actually runs.
detekt {
  buildUponDefaultConfig = true
  config.from(files("detekt.yml"))
}

dependencies {
  detektPlugins(project(":crypto-detekt-rules"))
}

val detektLintTasks = tasks.matching {
  it.name.startsWith("detekt") &&
      (it.name.endsWith("SourceSet") ||
          it.name == "detektMainAndroid" ||
          it.name == "detektTestJvm")
}

// Fix Gradle 9.6 implicit-dependency validation: detekt's baseline tasks
// produce XML files consumed by the lint tasks without declaring the dependency.
tasks
    .matching {
      it.name.startsWith("detekt") &&
          !it.name.startsWith("detektBaseline") &&
          (it.name.endsWith("SourceSet") ||
              it.name == "detektMainAndroid" ||
              it.name == "detektTestJvm")
    }
    .configureEach {
      val baselineTaskName = "detektBaseline${name.removePrefix("detekt")}"
      dependsOn(baselineTaskName)
    }

// kover (ADR-0007): 100% line + branch coverage on the pure-K JVM path.
// ADR-0002: actual dispatch wrappers delegate to *PureK; exclude from
// the 100% gate — the *PureK objects carry the real coverage.
kover {
  reports {
    total {
      filters {
        excludes {
          classes(
              "ch.trancee.meshlink.crypto.SHA256",
              "ch.trancee.meshlink.crypto.SHA512",
              "ch.trancee.meshlink.crypto.HMAC_SHA256",
              "ch.trancee.meshlink.crypto.HKDF_SHA256",
              "ch.trancee.meshlink.crypto.X25519",
              "ch.trancee.meshlink.crypto.Ed25519",
              "ch.trancee.meshlink.crypto.ChaCha20Poly1305",
              "ch.trancee.meshlink.crypto.CryptoProviderKt",
              "ch.trancee.meshlink.crypto.CryptoBridgeKt",
          )
        }
      }
      xml { onCheck = true }
      html { onCheck = (findProperty("koverHtmlOnCheck")?.toString() ?: "true") != "false" }
      verify {
        rule {
          minBound(100)
          minBound(100, kotlinx.kover.gradle.plugin.dsl.CoverageUnit.BRANCH)
        }
      }
    }
  }
}

tasks.named("koverXmlReport") {
  outputs.upToDateWhen { false }
}

tasks.named("check") {
  dependsOn(detektLintTasks)
}

// Spotless + ktfmt: the single owner of Kotlin style (ADR-0007).
spotless {
  kotlin {
    target("src/**/*.kt")
    ktfmt()
  }
  kotlinGradle {
    target("*.kts")
    ktfmt()
  }
}

// Dokka (ticket 01): KDoc generation from the start. Apply-only; Dokka derives the
// module name from the project and creates the `dokkaGenerate` task.

// Publishing configuration for Maven Central.
// KMP auto-registers MavenPublication per target. Configure shared POM metadata
// and PGP signing. Credentials read from Gradle properties (set locally via
// ~/.gradle/gradle.properties or as env vars.
publishing {
  publications.withType<MavenPublication> {
    pom {
      name.set("MeshLink-crypto")
      description.set(
          "Pure-Kotlin, constant-time cryptographic primitives for Kotlin Multiplatform," +
              " with per-primitive native fallback."
      )
      url.set("https://github.com/trancee/MeshLink-crypto")
      licenses {
        license {
          name.set("Apache License, Version 2.0")
          url.set("https://www.apache.org/licenses/LICENSE-2.0")
        }
      }
      developers {
        developer {
          id.set("trancee")
          name.set("Trancee")
          url.set("https://github.com/trancee")
        }
      }
      scm {
        connection.set("scm:git:git://github.com/trancee/MeshLink-crypto.git")
        developerConnection.set("scm:git:ssh://github.com/trancee/MeshLink-crypto.git")
        url.set("https://github.com/trancee/MeshLink-crypto")
      }
    }
  }

  // Maven Central repository: credentials from Gradle properties or env vars.
  repositories {
    maven {
      name = "MavenCentral"
      url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
      credentials {
        username = findProperty("MAVEN_CENTRAL_USERNAME") as String?
            ?: System.getenv("MAVEN_CENTRAL_USERNAME") ?: ""
        password = findProperty("MAVEN_CENTRAL_PASSWORD") as String?
            ?: System.getenv("MAVEN_CENTRAL_PASSWORD") ?: ""
      }
    }
  }
}

// Signing: PGP-sign all published artifacts.
// In CI, signing config is passed via environment variables (SIGNING_KEY_ID,
// SIGNING_KEY, SIGNING_KEY_PASSWORD) because the PGP key block is multi-line
// and breaks -P flag shell expansion. Locally, set them in
// ~/.gradle/gradle.properties or export as env vars.
signing {
  val signingKeyId: String? = findProperty("signingKeyId") as String?
      ?: System.getenv("SIGNING_KEY_ID")
  val signingKey: String? = findProperty("signingKey") as String?
      ?: System.getenv("SIGNING_KEY")
  val signingPassword: String? = findProperty("signingKeyPassword") as String?
      ?: System.getenv("SIGNING_KEY_PASSWORD")
  if (signingKey != null && signingKeyId != null) {
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
  }
}

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

// iOS native tests (iosArm64Test) require a connected iOS device and are disabled.
// The pure-K path is covered by the JVM suite + kover; native dispatch is
// validated by the compile-abiValidation gate. (ADR-0007 / ticket 01.)
tasks
    .matching {
      it.name.startsWith("ios") && it.name.endsWith("Test")
    }
    .configureEach {
      enabled = false
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
  // Rename published artifactIds from "crypto-*" to "meshlink-crypto*".
  // The project dir is still "crypto/"; only the Maven coordinates change.
  // Gradle consumers resolve platform variants via module metadata automatically.
  // Maven consumers use the explicit artifactIds. iosSimulatorArm64 was dropped:
  // only iosArm64 (device) is needed for distribution; the simulator build is a
  // local dev concern only.
  // withType<MavenPublication> is lazy: on non-macOS CI hosts the iosArm64
  // publication may not exist, but configureEach skips it gracefully.
  publications.withType<MavenPublication> {
    val targetName = name
    setArtifactId(
        when (targetName) {
          "kotlinMultiplatform" -> "meshlink-crypto"
          "android" -> "meshlink-crypto-android"
          "jvm" -> "meshlink-crypto-jvm"
          "iosArm64" -> "meshlink-crypto-ios"
          else -> targetName
        }
    )
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

  // Maven Central / Central Portal repository.
  // Migrated from s01.oss.sonatype.org (legacy OSSRH, returns HTTP 402
  // Payment Required when account is on the Central Portal) to the
  // Central Portal's OSSRH Staging API compatibility endpoint.
  // Credentials must be Central Portal User Tokens (generated at
  // https://central.sonatype.com/), NOT legacy OSSRH tokens.
  // See: https://central.sonatype.org/publish/publish-portal-ossrh-staging-api/
  repositories {
    maven {
      name = "MavenCentral"
      url =
          uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
      credentials {
        username =
            findProperty("MAVEN_CENTRAL_USERNAME") as String?
                ?: System.getenv("MAVEN_CENTRAL_USERNAME")
                ?: ""
        password =
            findProperty("MAVEN_CENTRAL_PASSWORD") as String?
                ?: System.getenv("MAVEN_CENTRAL_PASSWORD")
                ?: ""
      }
    }
  }
}

// Signing: PGP-sign all published artifacts.
// In CI, signing config is passed via environment variables (SIGNING_KEY,
// SIGNING_KEY_PASSWORD) because the PGP key block is multi-line and breaks
// -P flag shell expansion. Locally, set them in ~/.gradle/gradle.properties
// or export as env vars. The keyId is passed as null so the signing plugin
// extracts it from the PGP private key block itself.
signing {
  val signingKey: String? = findProperty("signingKey") as String? ?: System.getenv("SIGNING_KEY")
  val signingPassword: String? =
      findProperty("signingKeyPassword") as String? ?: System.getenv("SIGNING_KEY_PASSWORD")
  if (signingKey != null) {
    // Normalize line endings: GitHub Secrets may inject CRLF which BouncyCastle
    // (used by the signing plugin) cannot parse, even though gpg handles it fine.
    var normalizedKey = signingKey.trim().replace("\r\n", "\n").replace("\r", "\n")
    // Some secret managers store keys with literal backslash-n sequences
    // instead of actual newline characters. Convert them to real newlines.
    normalizedKey = normalizedKey.replace("\\n", "\n").replace("\\r", "\n")
    // Some secret managers store the key without ASCII armor headers.
    // Wrap in standard PGP private key block delimiters if missing.
    if (!normalizedKey.contains("BEGIN PGP")) {
      normalizedKey =
          "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n$normalizedKey\n-----END PGP PRIVATE KEY BLOCK-----"
    }
    useInMemoryPgpKeys(null as String?, normalizedKey, signingPassword)
    sign(publishing.publications)
  }
}

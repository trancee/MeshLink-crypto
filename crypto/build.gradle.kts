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
// Maven Central requires a Javadoc JAR for JVM publications (ADR-0007).
// For Kotlin KMP projects, Dokka HTML output serves as the Javadoc replacement.
tasks.register<Jar>("javadocJarJvm") {
  archiveClassifier.set("javadoc")
  from(tasks.named("dokkaGenerateHtml"))
}

// Sources JARs: Central Portal requires sources JARs for all publications.
// KMP auto-generates <target>SourcesJar tasks (jvmSourcesJar, androidSourcesJar,
// iosArm64SourcesJar, etc.) and attaches them to each target's publication.
// We only need to manually attach the Javadoc JAR (Dokka HTML) for JVM.

// Central Portal Publisher API bundle: zips the local Maven repo into a
// single archive for upload via POST /api/v1/publisher/upload.
// See: .agents/skills/central-portal-publish/SKILL.md
tasks.register<Zip>("centralBundle") {
  archiveFileName.set("central-bundle.zip")
  from(layout.buildDirectory.dir("maven-bundle"))
  destinationDirectory.set(layout.buildDirectory.dir("distributions"))
  // Ensure signed artifacts are written to the local repo before zipping.
  dependsOn("publish")
}

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
    // Javadoc JAR: Central Portal requires it for JVM publications.
    // Sources JARs are auto-attached by KMP (jvmSourcesJar, androidSourcesJar, etc.).
    if (targetName == "jvm") {
      artifact(tasks.named("javadocJarJvm"))
    }
    // Android: KMP Android plugin already attaches androidSourcesJar to
    // the "android" publication — no manual sources JAR needed (would conflict).
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

  // Local file repository for Central Portal Publisher API bundle upload.
  // Artifacts (including PGP signatures, javadoc, and sources JARs) are
  // written here, then zipped into central-bundle.zip and uploaded via
  // POST /api/v1/publisher/upload. No remote credentials needed —
  // authentication to the Central Portal happens via Bearer token in CI.
  // See: .agents/skills/central-portal-publish/SKILL.md
  repositories {
    maven {
      name = "localBundle"
      url = uri(layout.buildDirectory.dir("maven-bundle"))
    }
  }
}

// Signing: PGP-sign all published artifacts.
// In CI, the signing key is passed as ORG_GRADLE_PROJECT_signingInMemoryKey /
// _Password env vars → Gradle project properties "signingInMemoryKey" /
// "signingInMemoryKeyPassword". The signing plugin auto-detects only
// the dotted "signing.inMemoryKey" / "signing.password" properties, so we
// wire the camelCase ones explicitly via useInMemoryPgpKeys() — no key
// normalization block needed. Locally, set signing.keyId, signing.password,
// and signing.secretKeyRingFile in ~/.gradle/gradle.properties.
signing {
  val key = findProperty("signingInMemoryKey") as String?
  val pass = findProperty("signingInMemoryKeyPassword") as String?
  if (key != null) {
    useInMemoryPgpKeys(key, pass)
  }
  sign(publishing.publications)
}

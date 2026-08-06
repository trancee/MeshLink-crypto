@file:OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)

plugins {
  alias(libs.plugins.kotlinMultiplatform)
  alias(libs.plugins.androidLibrary)
  alias(libs.plugins.detekt)
  alias(libs.plugins.kover)
  alias(libs.plugins.spotless)
  alias(libs.plugins.dokka)
}

group = "dev.omp.cryptokmp"

version = "0.1.0-SNAPSHOT"

kotlin {
  jvmToolchain(21)

  // JVM target.
  jvm()

  // Android target — under the AGP-9 Kotlin Multiplatform library plugin, the AGP
  // android config lives INSIDE `kotlin { android { } }` (there is no top-level
  // `android {}` extension). See:
  // https://developer.android.com/kotlin/multiplatform/plugin
  android {
    namespace = "dev.omp.cryptokmp"
    compileSdk = 37
    minSdk = 21
    // targetSdk omitted: library module — AGP 9.x deprecated targetSdk in a
    // library default config; the consuming app sets the rollout target (ADR-0007).
  }

  iosArm64()
  iosX64()
  iosSimulatorArm64()

  sourceSets {
    // Gradle 9.6: the `getting` delegate is deprecated-as-error; use getByName.
    getByName("commonTest") {
      dependencies {
        implementation(kotlin("test"))
      }
    }
  }

  // Binary compatibility validation via the KGP built-in ABI dumper (ADR-0007).
  // `abiValidation {}` enables it; `checkKotlinAbi`/`updateKotlinAbi` auto-wire to
  // `check`; `updateKotlinAbi` writes the reference dump (committed under
  // crypto-kmp/api) so CI detects ABI drift. Experimental in KGP 2.4.10 — opted in
  // at file top via @OptIn(ExperimentalAbiValidation).
  // Docs: https://kotlinlang.org/docs/gradle-binary-compatibility-validation.html
  abiValidation {}
}

// iOS (native) tests require a running simulator/device to execute; disable
// *execution* (not compilation) so `:check` is green on any host. iOS binaries
// still compile (metadata + KLib) and feed the abiValidation gate, and the common
// test suite still runs on the JVM (covered by kover). (ADR-0007 / ticket 01.)
tasks
    .matching {
      it.name.startsWith("ios") && it.name.endsWith("Test")
    }
    .configureEach {
      enabled = false
    }

// detekt (ADR-0007): 2.0's top-level `detekt` task is a no-source aggregator; the
// per-source-set `detekt*SourceSet` / `detektMainAndroid` / `detektTestJvm` tasks
// are the real linters. Wire `check` to them so static analysis actually runs.
// gradle/detekt.yml (with the ADR-0003 constant-time rule) lands in ticket 02.
detekt {
  buildUponDefaultConfig = true
}

val detektLintTasks = tasks.matching {
  it.name.startsWith("detekt") &&
      (it.name.endsWith("SourceSet") ||
          it.name == "detektMainAndroid" ||
          it.name == "detektTestJvm")
}

// kover (ADR-0007): 100% line + branch coverage on the pure-K JVM path.
// `total { xml { onCheck = true }; verify { rule {} } }` auto-wires the koverVerify
// gate + the XML report onto `check`; keep the XML report always regenerated.
kover {
  reports {
    total {
      xml { onCheck = true }
      html { onCheck = true }
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

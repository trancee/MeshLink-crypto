@file:OptIn(org.jetbrains.kotlin.gradle.dsl.abi.ExperimentalAbiValidation::class)

plugins {
  alias(libs.plugins.kotlinMultiplatform)
  alias(libs.plugins.androidLibrary)
  alias(libs.plugins.detekt)
  alias(libs.plugins.kover)
  alias(libs.plugins.spotless)
  alias(libs.plugins.dokka)
  alias(libs.plugins.kotlinxBenchmark)
  alias(libs.plugins.kotlinAllOpen)
}

group = "ch.trancee.meshlink"

version = "0.1.0-SNAPSHOT"

kotlin {
  jvmToolchain(21)

  // JVM target.
  // Separate 'benchmark' compilation for JMH microbenchmarks (kotlinx-benchmark guide:
  // "Setting Up a Separate Source Set for Benchmarks"). associateWith links the
  // benchmark compilation to 'main' so benchmark code can access library internals.
  jvm {
    val jvmTarget = this
    compilations {
      create("benchmark") {
        associateWith(jvmTarget.compilations.getByName("main"))
      }
    }
  }

  // Android target — under the AGP-9 Kotlin Multiplatform library plugin, the AGP
  // android config lives INSIDE `kotlin { android { } }` (there is no top-level
  // `android {}` extension). See:
  // https://developer.android.com/kotlin/multiplatform/plugin
  android {
    namespace = "ch.trancee.meshlink.crypto"
    compileSdk = 37
    minSdk = 21
    // targetSdk omitted: library module — AGP 9.x deprecated targetSdk in a
    // library default config; the consuming app sets the rollout target (ADR-0007).
  }

  iosArm64()
  iosSimulatorArm64()

  sourceSets {
    // Gradle 9.6: the `getting` delegate is deprecated-as-error; use getByName.
    getByName("commonTest") {
      dependencies {
        implementation(kotlin("test"))
      }
    }
    // Benchmark source set — depends on kotlinx-benchmark-runtime for annotations.
    // Not part of the shipped library: only the 'benchmark' compilation uses it.
    getByName("jvmBenchmark") {
      dependencies {
        implementation(libs.kotlinxBenchmarkRuntime)
      }
    }
  }

  // Binary compatibility validation via the KGP built-in ABI dumper (ADR-0007).
  // `abiValidation {}` enables it; `checkKotlinAbi`/`updateKotlinAbi` auto-wire to
  // `check`; `updateKotlinAbi` writes the reference dump (committed under
  // crypto/api) so CI detects ABI drift. Experimental in KGP 2.4.10 — opted in
  // at file top via @OptIn(ExperimentalAbiValidation).
  // Docs: https://kotlinlang.org/docs/gradle-binary-compatibility-validation.html
  compilerOptions {
    freeCompilerArgs = listOf("-Xexpect-actual-classes")
  }
  abiValidation {}
}

// iOS (native) tests require a running simulator/device to execute. On macOS we enable
// the arm64 iOS simulator test (iosSimulatorArm64Test) to validate native dispatch
// interop (ADR-0002) via InteropHarnessTest (commonTest, which uses kotlin.test —
// multiplatform, no JUnit 5 tags needed). The legacy iosX64 target (x86_64 simulator)
// has been removed: Apple Silicon ci runners (macos-latest) use arm64 simulators,
// and x86_64 simulators require manual Rosetta setup. Physical-device tests
// (iosArm64Test) remain disabled — they need a connected iOS device. On non-macOS
// hosts all iOS tests are disabled so `:check` is green for local development.
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
// NOTE: tests live in jvmTest (not commonTest) to enable JUnit 5 @Tag. The jvmTest
// suite covers the pure-K path with full kover coverage on JVM. iOS tests (below)
// now run on macOS via InteropHarnessTest in commonTest, which uses kotlin.test
// (multiplatform) and compares native dispatch vs pure-K on each platform.
tasks.named<org.gradle.api.tasks.testing.Test>("jvmTest") {
  useJUnitPlatform {
    // includeTags("positive", "critical-path")
    // includeTags("timing")  // opt-in: timing variance assertions (ADR-0003 §4)
  }
}

// detekt (ADR-0007): 2.0's top-level `detekt` task is a no-source aggregator; the
// per-source-set `detekt*SourceSet` / `detektMainAndroid` / `detektTestJvm` tasks
// are the real linters. Wire `check` to them so static analysis actually runs.
// gradle/detekt.yml (with the ADR-0003 constant-time rule) lands in ticket 02.
detekt {
  buildUponDefaultConfig = true
  config.from(files("detekt.yml"))
}

dependencies {
  // Custom detekt rule set enforcing constant-time discipline on :crypto's
  // common sources (ADR-0003, ticket 02). Registered via the ServiceLoader in
  // :crypto-detekt-rules and loaded into the detekt tasks below.
  detektPlugins(project(":crypto-detekt-rules"))
}

val detektLintTasks = tasks.matching {
  it.name.startsWith("detekt") &&
      (it.name.endsWith("SourceSet") ||
          it.name == "detektMainAndroid" ||
          it.name == "detektTestJvm") &&
      // Exclude benchmark source sets from detekt — JMH annotation-heavy code
      // would trip style rules (MaxLineLength, MagicNumber, etc.).
      !it.name.contains("Benchmark") &&
      // Exclude baseline-generation tasks: they're prerequisites, not linters.
      !it.name.contains("Baseline")
}

// Fix Gradle 9.6 implicit-dependency validation: detekt's baseline tasks
// produce XML files consumed by the lint tasks without declaring the dependency.
// Wire the dependency explicitly so Gradle 9 doesn't reject the task graph.
tasks
    .matching {
      it.name.startsWith("detekt") &&
          !it.name.startsWith("detektBaseline") &&
          (it.name.endsWith("SourceSet") ||
              it.name == "detektMainAndroid" ||
              it.name == "detektTestJvm") &&
          !it.name.contains("Benchmark")
    }
    .configureEach {
      val baselineTaskName = "detektBaseline${name.removePrefix("detekt")}"
      dependsOn(baselineTaskName)
    }

// kover (ADR-0007): 100% line + branch coverage on the pure-K JVM path.
// `total { xml { onCheck = true }; verify { rule {} } }` auto-wires the koverVerify
// gate + the XML report onto `check`; keep the XML report always regenerated.
kover {
  reports {
    total {
      // Exclude benchmark code from coverage: benchmarks are dev-only tooling
      // (ADR-0005) and have no tests. Including them would drop coverage below the 100% gate.
      filters {
        excludes {
          // ADR-0009: wildcard covers every `*Benchmark` class -- new primitives self-excluded.
          classes("ch.trancee.meshlink.crypto.*Benchmark")
          // ADR-0002: actual dispatch wrappers delegate to *PureK; exclude from
          // the 100% gate - the *PureK objects carry the real coverage.
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

// allopen: JMH generates subclasses of benchmark classes at runtime;
// the plugin opens any class annotated with @State so JMH can subclass it.
// (Without this, Kotlin 'final' classes crash JMH's bytecode generation.)
allOpen {
  annotation("org.openjdk.jmh.annotations.State")
}

// kotlinx-benchmark (ticket 03): JMH-backed microbenchmarks for JVM.
// The target name must match the source set name ('jvmBenchmark') when using
// a separate compilation — see the plugin's "Separate source set for benchmarks" guide.
benchmark {
  configurations {
    named("main") {
      warmups = 2
      iterations = 3
      iterationTime = 1
      iterationTimeUnit = "SECONDS"
    }
  }
  targets {
    register("jvmBenchmark") {}
  }
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

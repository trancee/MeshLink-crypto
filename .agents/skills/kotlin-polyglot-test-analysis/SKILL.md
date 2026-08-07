---
name: kotlin-polyglot-test-analysis
description: >-
  Polyglot test quality analysis skills adapted for Kotlin Multiplatform.
  Installs six analysis skills (anti-patterns, smell detection, assertion
  quality, gap analysis, tagging, grading) plus the test-quality-auditor agent
  workflow, with the Kotlin extension data bundled as a required dependency.
  .NET-only skills are excluded.
license: MIT
---

# Polyglot Test Analysis for Kotlin Multiplatform

This managed skill installs the polyglot (language-agnostic) subset of the
[`dotnet-test` plugin](https://github.com/dotnet/skills/tree/main/plugins/dotnet-test)
tailored for this Kotlin Multiplatform (KMP) cryptography project.

## Project Testing Stack

| Aspect | Technology |
|--------|-----------|
| Build | Gradle 9.6, Kotlin DSL, Kotlin 2.4.10 |
| Test framework | `kotlin.test` (maps to **JUnit 5 / Jupiter** on JVM) |
| Coverage | **Kover** — 100% line + branch gate on the pure-K JVM path |
| Static analysis | **detekt** (incl. custom constant-time lint via `:crypto-detekt-rules`) |
| Formatting | **ktfmt** + spotless |
| Test sources | `crypto/src/commonTest/kotlin/ch/trancee/meshlink/crypto/` |
| Build convention | `./gradlew test --rerun --no-build-cache` (never use build cache) |

## Installed Polyglot Skills

| Skill | Purpose | When to invoke |
|-------|---------|-----------------|
| `test-anti-patterns` | Pragmatic scan for anti-patterns (Critical/High/Medium/Low) | Quick audit: "are my tests good?", flakiness, assertion-free tests |
| `test-smell-detection` | Deep formal audit using the 19-smell academic taxonomy (testsmells.org) | When asked for citable smell names or thorough structural audit |
| `assertion-quality` | Assertion variety and depth metrics across 12 categories | "Are my assertions shallow?", assertion diversity analysis |
| `test-gap-analysis` | Pseudo-mutation analysis — finds blind spots coverage numbers miss | "Would my tests catch a bug?", boundary/edge-case gaps |
| `test-tagging` | Trait tagging (positive, negative, boundary, critical-path, etc.) | Categorizing tests, understanding distribution (auto-edit for JUnit 5) |
| `grade-tests` | Per-test letter grades (A–F) for PR comments | Grading a curated list of changed/new tests |
| `test-quality-auditor` (agent) | Orchestrates the above into a unified audit pipeline | Broad "audit my tests" / "test health check" requests |

## Excluded (.NET-only skills)

The following from the dotnet-test plugin are **not** installed because they
are .NET-specific and have no polyglot equivalent:

`run-tests`, `mtp-hot-reload`, `coverage-analysis`, `crap-score`,
`detect-static-dependencies`, `generate-testability-wrappers`,
`migrate-static-to-wrapper`, `platform-detection`, `filter-syntax`,
`writing-mstest-tests`, `code-testing-agent` (test *generation* pipeline —
not a quality *analysis* skill), and all `code-testing-*` internal subagents.

For Kotlin coverage, use Kover directly (`./gradlew koverXmlReport`).

## Required Dependency: Kotlin Extension Data

All six analysis skills below load per-language reference data. This skill
bundles the `test-analysis-extensions` dependency: the `kotlin.md` extension
file from the dotnet-test plugin. Use it as the source of truth for
framework-specific detection.

### Extension Reference: `kotlin.md`

```
# Kotlin Test Frameworks Reference (JUnit 5, Kotest, MockK)
Reference data for analyzing Kotlin test code. Used by the polyglot test analysis skills.

## Capability tags
| Capability | Support |
|------------|---------|
| Test discovery | Strong — JUnit 5 conventions, Kotest spec classes |
| Assertion detection | Strong — JUnit + Kotest matchers + MockK verifications |
| Sleep/delay detection | Strong — `Thread.sleep`, `delay()` |
| Skip/ignore detection | Strong — `@Disabled`, `.config(enabled = false)` |
| Setup/teardown detection | Strong — JUnit + Kotest lifecycle |
| Tag support | **auto-edit** — JUnit 5 `@Tag`, Kotest `tags`, project-defined |

## Test File Identification
| Framework | File convention | Test method markers |
|-----------|----------------|---------------------|
| JUnit 5 (Jupiter) | `*Test.kt`, `*Tests.kt`, `*IT.kt` | `@Test fun foo()` |
| Kotest | `*Spec.kt` (any style) | inherits a spec class (`StringSpec`, `FunSpec`, `BehaviorSpec`, `ShouldSpec`, `DescribeSpec`, `FeatureSpec`, `WordSpec`, `FreeSpec`, `AnnotationSpec`) |
| Spek | `*Spec.kt` | `object FooSpec : Spek({ ... })` |
| TestNG | `*Test.kt` | `@Test fun foo()` (TestNG annotation) |

## Assertion APIs
| Category | JUnit 5 (`Assertions`) | Kotest matchers | AssertK |
|----------|------------------------|-----------------|---------|
| Equality | `assertEquals(expected, actual)` | `actual shouldBe expected` | `assertThat(actual).isEqualTo(expected)` |
| Boolean | `assertTrue(b)` / `assertFalse(b)` | `b.shouldBeTrue()` / `b.shouldBeFalse()` | `assertThat(b).isTrue()` |
| Null | `assertNull(x)` / `assertNotNull(x)` | `x.shouldBeNull()` / `x.shouldNotBeNull()` | `assertThat(x).isNull()` |
| Throws | `assertThrows<SomeException> { … }` | `shouldThrow<SomeException> { … }` | `assertFailure { … }.isInstanceOf(SomeException::class)` |
| Type | `assertTrue(x is T)` | `x.shouldBeInstanceOf<T>()` | `assertThat(x).isInstanceOf(T::class)` |
| String | `assertTrue(s.contains(sub))` | `s shouldContain sub` / `s shouldMatch Regex("...")` | `assertThat(s).contains(sub)` |
| Collection | `assertIterableEquals(...)` | `col shouldContainExactly listOf(...)` | `assertThat(col).containsExactly(...)` |
| Coroutine result | `runTest { ... }` block + assertEquals | `coroutineScope { ... } shouldBe expected` | within `runTest` |
| Fail | `fail("reason")` | `fail("reason")` (Kotest) | `Assertions.fail("reason")` |

MockK verifications: `verify(exactly = 1) { mock.method() }` — counts as a state/side-effect assertion.

## Sleep/Delay Patterns
| Pattern | Example |
|---------|---------|
| Thread sleep | `Thread.sleep(2000)` |
| Coroutine delay | `delay(1000)` inside `runBlocking { ... }` |
| Acceptable (coroutine test) | `runTest { advanceTimeBy(1000) }` (virtual time, no real wait) |
| Awaitility-style | `Awaitility.await().atMost(5, SECONDS).until { ... }` |

Real `delay` inside `runBlocking { }` is a sleep smell; inside `runTest { }` it's virtual time and acceptable.

## Skip/Ignore Annotations
| Framework | Annotation |
|-----------|------------|
| JUnit 5 | `@Disabled`, `@Disabled("reason")`, `@DisabledIf(...)`, `@EnabledIf(...)`, `@DisabledOnOs(OS.WINDOWS)` |
| JUnit 5 (dynamic) | `Assumptions.assumeTrue(cond)` |
| Kotest | `.config(enabled = false)`, `xtest("…")`, `xshould("…")`, `xdescribe("…")` |
| Kotest (project-wide) | `EnabledCondition` / `EnabledIf` extensions |
| TestNG | `@Test(enabled = false)`, `throw SkipException("reason")` |

## Exception Handling — Idiomatic Alternatives
JUnit 5: `val ex = assertThrows<InvalidOrderException> { service.placeOrder(emptyOrder) }`
Kotest: `val ex = shouldThrow<InvalidOrderException> { ... }`
AssertK: `assertFailure { ... }.isInstanceOf(...).messageContains("...")`

Flag manual `try { ... fail() } catch (e: SomeException) { ... }` patterns.

## Mystery Guest — Common Kotlin/Android Patterns
| Indicator | What to look for |
|-----------|------------------|
| File system | `File(path).readText()`, hard-coded paths |
| Database | `Room.databaseBuilder(...)` without `inMemoryDatabaseBuilder` |
| Network | `Retrofit.create<…>()` against a real base URL, `OkHttp` without `MockWebServer` |
| Environment | `System.getenv("X")` |
| Android | `Context.assets.open(...)`, file system writes |
| Acceptable | `MockWebServer`, `MockK`, `inMemoryDatabaseBuilder`, `@MockK`, Robolectric, `TemporaryFolder` |

## Integration Test Markers
- File suffix: `*IT.kt`, `*IntegrationTest.kt`, `*E2ETest.kt`
- Annotations: `@SpringBootTest`, `@DataJpaTest`, `@Tag("integration")`
- Kotest tags: `tag = listOf(IntegrationTag)`
- Android: `androidTest/` source set is on-device/instrumented (integration); `test/` is JVM (unit)

## Setup/Teardown
| Framework | Per-test | Per-class |
|-----------|----------|-----------|
| JUnit 5 | `@BeforeEach` | `@BeforeAll` (must be `@JvmStatic` in companion object unless `@TestInstance(PER_CLASS)`) |
| JUnit 5 | `@AfterEach` | `@AfterAll` |
| Kotest | `beforeTest { }` / `beforeEach { }` | `beforeSpec { }` |
| Kotest | `afterTest { }` / `afterEach { }` | `afterSpec { }` |
| TestNG | `@BeforeMethod` | `@BeforeClass`, `@BeforeSuite` |
| Spek | `beforeEachTest { }` | `beforeGroup { }` |

## Tag/Trait Attributes (for `test-tagging`)
| Framework | Tag mechanism | Example |
|-----------|---------------|---------|
| JUnit 5 | `@Tag("positive")` (stackable) | `@Tag("positive") @Tag("critical-path")` |
| Kotest | per-test: `.config(tags = setOf(Positive))`; per-spec: `override fun tags() = setOf(Positive)` | tag objects: `object Positive : Tag()` |
| TestNG | `@Test(groups = ["positive"])` | `@Test(groups = ["positive", "boundary"])` |

## Language-specific calibration notes
- **Coroutine tests must use `runTest` / `runBlocking`** at the boundary; missing wrapper makes the test silently incomplete. Flag `suspend fun` test bodies without a coroutine scope.
- **`runBlocking` vs `runTest`:** `runBlocking` waits in real time; `runTest` uses virtual time. Prefer `runTest` for testing time-dependent code.
- **MockK `verify { }`** without `exactly = N` only checks at least once. Tests asserting exact behavior should set the count.
- **Kotest's `forAll(...)`** (data-driven) is parametrized, NOT duplicate tests.
- **`@OptIn(ExperimentalCoroutinesApi::class)`** is common in coroutine tests — not a smell.
- **Android `@MediumTest` / `@LargeTest`** are size annotations from `androidx.test.filters`; treat as integration markers.
- **Compose UI tests** (`createComposeRule`) are UI integration tests.
- **Bare `assert(x)` in tests** is the Kotlin `kotlin.assert` — acceptable but recommend framework matchers for richer failure messages.
- **`shouldBe` chained Kotest matchers** are single conceptual assertions; do not over-count chain length.
```

> **Project-specific note**: This project uses `kotlin.test` assertions (`assertEquals`, `assertTrue`, `assertContentEquals`, etc.) on top of JUnit 5. The Kotlin extension data above maps JUnit 5 (`Assertions`) and Kotest matchers. For this project, treat `kotlin.test` assertions as JUnit 5 equivalents (e.g., `kotlin.test.assertEquals` ≡ `Assertions.assertEquals`).

## Comprehensive Audit Pipeline

When the user asks for a broad test health check, run these skills in sequence:

### 1. Anti-patterns — `test-anti-patterns`

Quick pragmatic scan for Critical/High/Medium/Low issues. Uses the
Kotlin extension data above to detect:

- **Critical**: assertion-free tests, swallowed exceptions, always-true
  assertions, un-awaited async assertions, self-referential assertions
- **High**: wall-clock sleeps (`Thread.sleep`, `delay` in `runBlocking`),
  unseeded randomness, ordering dependencies, over-mocking, implementation
  coupling, broad exception assertions
- **Medium**: poor naming, magic values, duplicates, giant tests,
  assertion messages repeating the assertion, missing AAA separation
- **Low**: unused setup/teardown, print debugging, inconsistent naming

**Build command for verification**: `./gradlew :crypto:jvmTest --rerun --no-build-cache`

### 2. Assertion quality — `assertion-quality`

Classify every assertion into one of 12 categories (Equality, Boolean,
Null, Exception, Type, String, Collection, Comparison, Approximate,
Negative, State/Side-effect, Structural/Deep). Compute:

- Average assertions per test
- Assertion type spread (distinct categories used)
- Tests with zero assertions
- Tests with only trivial assertions (null/`isNotNull` checks)
- Tests with self-referential assertions
- Single-category tests

### 3. Test gaps — `test-gap-analysis`

Pseudo-mutation analysis of production code. For each mutation point
(boundary, boolean, return value, exception, arithmetic, null-check),
classify as:

- **Killed** — tests detect the mutation
- **Survived** — tests miss the mutation (gap)
- **No coverage** — no test exercises the path
- **Equivalent** — mutation produces identical behavior (skip)

**Critical for this project**: Every production method in `crypto/src/commonMain/`
should have at least one mutation that would be killed. Focus on:

- Boundary mutations in field arithmetic (`<=` vs `<`)
- Boolean flips in validation checks (`&&` vs `||`)
- Return value mutations (null returns, default values)
- Exception removal in guard clauses

**Verification procedure**:
1. Establish green baseline: `./gradlew :crypto:jvmTest --rerun --no-build-cache`
2. Apply each candidate survivor as a real edit
3. Re-run covering tests: `./gradlew :crypto:jvmTest --tests "*ClassName.testMethodName*" --rerun --no-build-cache`
4. Revert immediately after each check
5. Report: "N of M injected mutations were caught"

### 4. Test smells — `test-smell-detection` (optional, deep)

Uses the 19-smell academic taxonomy from testsmells.org. The 10 core
smells:

| # | Smell | Severity | Kotlin markers |
|---|-------|----------|----------------|
| 1 | Conditional Test Logic | High | `if`/`when`/`for` inside test body |
| 2 | Mystery Guest | High | `File(...)`, `System.getenv`, network without test doubles |
| 3 | Sleepy Test | High | `Thread.sleep`, `delay` in `runBlocking` |
| 4 | Assertion-Free Test | High | No `assert*`/`assertEquals` call; mock `verify` counts |
| 5 | Eager Test | Medium | 4+ distinct production methods called |
| 6 | Magic Number Test | Medium | Unexplained numeric literals in assertions |
| 7 | Sensitive Equality | Medium | `obj.toString()` comparison in assertions |
| 8 | Exception Handling in Tests | Medium | Manual `try`/`catch` instead of `assertThrows` |
| 9 | General Fixture | Low | Setup fields unused by most tests |
| 10 | Ignored/Disabled Test | Low | `@Disabled` or Kotest `xtest`/`xshould` |

The 9 additional smells (Assertion Roulette, Duplicate Assert, Lazy Test,
Constructor Initialization, Default Test, Redundant Print, Redundant
Assertion, Resource Optimism, Empty Test) are available for extended
analysis when requested.

## Test Tagging

For JUnit 5 (the platform this project uses on JVM), tagging is
**auto-edit**. Apply `@Tag("...")` attributes adjacent to existing
`@Test` annotations.

Register tag filters in `crypto/build.gradle.kts`:

```kotlin
tasks.named<Test>("jvmTest") {
    useJUnitPlatform {
        // Include only positive/critical-path tests by default in CI
        // includeTags("positive")
        // excludeTags("slow", "integration")
    }
}
```

Trait taxonomy (use exactly these values):

| Trait | When to apply |
|-------|---------------|
| `positive` | Verifies expected behavior under normal/valid conditions |
| `negative` | Verifies error handling or invalid input rejection |
| `boundary` | Tests `0`, empty, null, `Int.MAX_VALUE`, empty collections |
| `critical-path` | Core crypto primitives (SHA-256, SHA-512, X25519, Ed25519) |
| `smoke` | Quick sanity check (e.g., `VersionTest`) |
| `regression` | Reproduces a previously-reported bug |
| `security` | Constant-time discipline, timing attack resistance |
| `performance` | JMH microbenchmark tests |
| `flaky` | Known unstable tests |

**Kotlin-specific notes**:
- For `kotlin.test` on JVM, use `@Tag("...")` (JUnit 5 platform tag)
- The Kotlin extension declares `auto-edit` tag support for JUnit 5

## Grade Tests

Designed for PR-comment feedback. Input must be a curated list of test
methods (changed/new tests in a PR), not the entire workspace. For each
test, produce a letter grade (A–F) with score band and one-line note.

Weighting: 45% Assertion strength + 30% Anti-pattern hygiene + 25%
Structure & focus. Overall grade capped at the worst sub-grade.

## Skill Routing Guide

| User intent | Route to |
|-------------|----------|
| "Are my tests any good?" / quick check | `test-anti-patterns` → `test-quality-auditor` |
| "Audit my test suite" / health check | `test-quality-auditor` (full pipeline) |
| "Are my assertions shallow?" | `assertion-quality` |
| "Would tests catch a bug here?" | `test-gap-analysis` |
| "Find test smells" (academic taxonomy) | `test-smell-detection` |
| "Grade the tests in this PR" | `grade-tests` |
| "Tag my tests with traits" | `test-tagging` |

## Excluded from this installation

- .NET-only execution skills: `run-tests`, `mtp-hot-reload`
- .NET-only coverage/risk: `coverage-analysis`, `crap-score`
- .NET-only testability: `detect-static-dependencies`, `generate-testability-wrappers`, `migrate-static-to-wrapper`
- .NET-only reference: `platform-detection`, `filter-syntax`
- .NET-only writing: `writing-mstest-tests`
- Test generation pipeline: `code-testing-agent`, `code-testing-*` subagents
- Experimental: `exp-test-maintainability`, `exp-mock-usage-analysis`

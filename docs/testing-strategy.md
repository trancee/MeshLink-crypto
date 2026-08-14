# Testing Strategy: Android SDK Dispatch Verification

## Problem

The library uses a per-primitive native-or-pure-K fallback (ADR-0002). On Android,
JCA provides SHA-256, SHA-512, HMAC-SHA-256, and HKDF-SHA-256 natively on all API
levels. But X25519, Ed25519, and ChaCha20-Poly1305 are only in JCA starting at
API 29 (`AndroidKeyStore` / `javax.crypto`). On SDK 21–28, those three primitives
must fall back to the PureK implementation.

Verifying the actual Android runtime dispatch requires an Android emulator or
physical device. However, Kotlin Multiplatform with AGP 9.x does **not** auto-create
an `androidInstrumentedTest` source set or an `androidUnitTest` source set — only
`compileAndroidMain` exists for the Android target.

## Strategy

Three complementary test layers cover dispatch correctness:

### 1. DispatchVerificationTest (commonTest)

Runs on JVM and iOS simulator. Calls each public API entry point and verifies the
result against RFC known-answer test vectors (KAT). This proves the native dispatch
path produces correct results on each platform's native crypto provider.

- **JVM**: All primitives use JCA (JDK 21 supports all of them).
- **iOS**: SHA-256, SHA-512, HMAC, HKDF, X25519, Ed25519 use Darwin native
  (CommonCrypto / Security.framework). ChaCha20-Poly1305 falls back to PureK
  (no CryptoKit C-API).

### 2. PureKFallbackVerificationTest (commonTest)

Runs on JVM and iOS simulator. Calls the `*PureK` objects directly (bypassing the
dispatch bridge) and verifies they produce identical RFC KAT results. This proves
the fallback implementations are correct — the only thing that matters on Android SDK
21–28, where those primitives run on the PureK path.

### 3. DispatchBridgeTest (jvmTest)

Uses JVM reflection to set the `x25519Fallback`, `ed25519Fallback`, and
`chacha20Poly1305Fallback` flags in `CryptoBridge.kt` to `true`. This simulates
the Android SDK 21–28 condition where JCA throws `NoSuchAlgorithmException`.

The test then verifies:
- The `native` function returns `null` (flag check short-circuits)
- The public API entry point falls back to PureK via the `elvis` operator
- The PureK result matches the RFC KAT vectors

The fallback flags are `@Volatile private var` fields in the platform `CryptoBridge`
file. The `jvmMain/CryptoBridge.kt` and `androidMain/CryptoBridge.kt` have identical
field names, so the reflection works on JVM to simulate Android behavior.

After each test, the flags are reset to `false` in an `@AfterTest` block to avoid
side effects on other tests.

## CI Matrix: Compile Verification

The `android-matrix` CI job verifies that `compileAndroidMain` succeeds for SDK 21,
28, 29, and 37. These jobs confirm the Android source set compiles against each
target API level. They do **not** run runtime tests — see the CI workflow comment
and the notes below.

**Key decision**: `compileSdk` is a compile-time concept. Setting
`-PcompileSdkOverride=21` means the Android source set is compiled against the
Android 21 SDK. It does **not** mean tests run on Android 21. On CI, the `:crypto:jvmTest`
task runs on JDK 21 where JCA supports all primitives natively.

## SDK-Level Dispatch Summary

| Android API | SHA-256 | SHA-512 | HMAC-SHA-256 | HKDF-SHA-256 | X25519 | Ed25519 | ChaCha20-Poly1305 |
|---|---|---|---|---|---|---|---|
| 21–24 | JCA | JCA | JCA | JCA | PureK | PureK | PureK |
| 25–28 | JCA | JCA | JCA | JCA | PureK | PureK | PureK |
| 29+ | JCA | JCA | JCA | JCA | JCA | JCA | JCA |
| JVM (JDK 21) | JCA | JCA | JCA | JCA | JCA | JCA | JCA |

## CI Summary Transparency

The `scripts/ci-summary.py` script generates a GitHub Actions summary with:

1. **Coverage table**: kover branch + instruction coverage percentages
2. **Test results table**: per-platform test counts (passed/failed/skipped)
3. **Dispatch verification table**: per-test dispatch path (native vs PureK)
   - `DispatchVerificationTest` → shows platform's native path
   - `PureKFallbackVerificationTest` → shows "PureK fallback"
   - `DispatchBridgeTest` fallback tests → shows "PureK fallback (simulated)"
4. **SDK notes**: transparent explanation that compileSdk is compile-time only
   and tests run on JVM (JDK 21)

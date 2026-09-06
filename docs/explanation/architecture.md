# Architecture

> **Explanation.** This page provides background. It explains the design and its rationale. For facts, see the [API Reference](../reference/api-reference.md) and [Supported Primitives](../reference/supported-primitives.md). For step-by-step goals, see the [How-to guides](../how-to/).

## What the library is

The library implements thirteen RFC/FIPS-standard primitives as pure-Kotlin, constant-time implementations. It also offers a native fallback path where the host platform already provides the same operation.

The library targets JVM, Android (API 21+), and iOS (arm64 + simulator). JS and WebAssembly targets are out of scope. See [CONTEXT.md](../../CONTEXT.md) for the full terminology glossary.

## Module layout

The project has two Gradle modules (see [ADR-0006](../adr/0006-module-layout.md)):

```text
:crypto                  The single KMP module. All primitives and dispatch live here.
:crypto-detekt-rules     A JVM-only subproject. Ships the custom ConstantTimeRule for detekt.
```

The root `build.gradle.kts` applies no plugins. Plugins are applied per-module via the version catalog (`gradle/libs.versions.toml`). This is intentional — it avoids the "Kotlin plugin loaded multiple times" warning.

The `:crypto` module source set structure:

```text
crypto/src/
├── commonMain/    expect declarations + pure-K implementations (shared engine)
├── commonTest/    Interop harness tests (run on all targets)
├── jvmMain/       JVM actuals + CryptoBridge (JCA dispatch)
├── androidMain/   Android actuals + CryptoBridge (JCA dispatch)
├── iosMain/       iOS actuals + CryptoBridge (CommonCrypto / Security.framework)
├── jvmTest/       Unit tests (JUnit 5, Wycheproof, KAT)
```

KMP source sets do **not** inherit across targets. `androidMain` does not extend `jvmMain`. This is why the JCA dispatch code is duplicated between JVM and Android. The iOS bridge uses Kotlin/Native cinterop to C frameworks (CommonCrypto, Security.framework) instead.

## The three-layer dispatch

Each primitive has three layers, in order of preference:

1. **Optional CryptoProvider** — a consuming app can inject a platform-native provider at runtime via `setCryptoProvider()`. This supports CryptoKit-backed implementations on iOS and custom JCA providers on JVM/Android.
2. **Native C-API / JCA** — the library calls the host platform's native crypto directly. On JVM/Android this is `java.security` / `javax.crypto`. On iOS this is CommonCrypto and Security.framework via Kotlin/Native cinterop.
3. **Pure-Kotlin fallback** — if the native path is unavailable (older API level, missing algorithm), the library falls back to its own pure-Kotlin implementation compiled from the same `commonMain` source.

The dispatch is **per-primitive**. A single target can use native SHA-256 and pure-K X25519 in the same process. Callers never select a provider.

### Dispatch flow

```text
Caller → Crypto / Hasher / Authenticator / Kdf / KeyExchange / Signer / Aead
  → expect/actual dispatch object (e.g. X25519)
    → CryptoBridge.x25519Native(scalar, u)   // native path
      ?: X25519PureK.compute(scalar, u)      // pure-K fallback
```

The thin `actual` objects (e.g. `jvmMain/.../X25519.kt`) contain no `@Secret`-annotated parameters. They delegate to `*Native()` functions in `CryptoBridge.kt` using the elvis operator (`?:`). If the native call returns `null`, the pure-K implementation runs.

## The pure-Kotlin engine

The pure-Kotlin implementations live in `commonMain`. Three arithmetic engines serve all primitives:

- **Radix-2^26 field engine** (`FieldElement`) — serves X25519 and Ed25519. Operates over GF(2^255−19). Uses 10 limbs, bitwise `cswap`, and no `BigInteger` (see [ADR-0001](../adr/0001-field-arithmetic-radix-2-26.md)). Both X25519 and Ed25519 share this engine.
- **32-bit / 64-bit word engine** — serves SHA-256, SHA-512, HMAC-SHA256, HKDF-SHA256, ChaCha20, Poly1305, and ChaCha20-Poly1305. Uses fixed-round arithmetic with no `BigInteger`.
- **NTT engine** (`MLDSANtt.kt`) — serves ML-DSA-44 (FIPS 204). Implements the number-theoretic transform over Z_q (q = 8380417) with 256 precomputed zetas, branch-free Montgomery and Barrett reduction.
- **ML-KEM-512 NTT engine** (`MLKEMNtt.kt`) — serves ML-KEM-512 (FIPS 203). Separate NTT implementation over Z_q (q = 3329) with 128 precomputed zetas, branch-free Montgomery and Barrett reduction. Cannot share ML-DSA's NTT — different field modulus requires separate zetas table and Montgomery constants.

The engines are independent. They do not share code.

## The @Secret annotation and the detekt rule

The `@Secret` annotation marks parameters that hold secret data. The `:crypto-detekt-rules` project ships a custom `ConstantTimeRule`. This rule scans each file for `@Secret`-annotated parameters. It then flags any `if`/`when` branch or array index that references a secret name.

The dispatch bridge files (`CryptoBridge.kt`) contain no `@Secret` parameters. This means the provider-selection and fallback branching is never flagged. Only the pure-K implementations — the code that actually handles secrets — are held to the constant-time lint.

## What is out of scope

Persistent key storage (Android Keystore key pairs, iOS Keychain) is out of scope for the core module (see [ADR-0004](../adr/0004-secure-storage-out-of-core-scope.md)). The library never persists keys. Callers own key bytes. The library wipes its internal buffers via `AutoCloseable` key handles.

SKIE is excluded from the build (see [ADR-0008](../adr/0008-skie-excluded.md)). The API is stateless, synchronous, no-throw, and uses `Result<T>`. There are no coroutines or `Flow` to bridge to Swift concurrency.

## Related reading

- [ADR-0001](../adr/0001-field-arithmetic-radix-2-26.md) — Field arithmetic
- [ADR-0002](../adr/0002-fallback-strategy.md) — Fallback strategy
- [ADR-0003](../adr/0003-verification-gates.md) — Verification gates
- [ADR-0004](../adr/0004-secure-storage-out-of-core-scope.md) — Secure storage scope
- [ADR-0005](../adr/0005-api-surface.md) — API surface
- [ADR-0006](../adr/0006-module-layout.md) — Module layout
- [ADR-0007](../adr/0007-build-quality-toolchain.md) — Build toolchain
- [Proposal: iOS Native Crypto](../proposals/0001-cryptokit-ios-native.md)
- [RFC 9794](https://datatracker.ietf.org/doc/html/rfc9794) — Terminology for post-quantum traditional hybrid schemes (PQ transition reference)
- [RFC 9958](https://datatracker.ietf.org/doc/html/rfc9958) — Post-Quantum Cryptography for Engineers (deployment guidance)
- [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180) — Hybrid Public Key Encryption (HPKE-ML-KEM reference for future KEM support)
- [RFC 9861](https://datatracker.ietf.org/doc/html/rfc9861) — KangarooTwelve and TurboSHAKE (Keccak family extensions reference)

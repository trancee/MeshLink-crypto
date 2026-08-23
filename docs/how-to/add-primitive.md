# How to: Add a Crypto Primitive

> **How-to guide.** This guide shows you how to add a new cryptographic primitive to the library. It assumes you understand the constant-time discipline and the three-layer dispatch architecture. For background, see [Architecture](../explanation/architecture.md).

## Before you start

A primitive is not done until it ships with its correctness vectors, green constant-time lint, and 100% coverage on the pure-Kotlin path. Open a GitHub issue first to track the work. See the issue checklist in [docs/agents/issue-tracker.md](../agents/issue-tracker.md).

## Step 1: Open an issue

Create an issue with the acceptance checklist pre-filled:

```bash
gh issue create \
  --title "Implement <Primitive> (RFC <number>)" \
  --body "...include the checklist from issue-tracker.md..."
```

## Step 2: Write the pure-Kotlin implementation

Place the implementation in `crypto/src/commonMain/kotlin/ch/trancee/meshlink/crypto/`.

- Name the file after the primitive (e.g. `Foo.kt`).
- Use the `*PureK` naming convention for the implementation object (e.g. `FooPureK`).
- Annotate all secret parameters with `@Secret`.
- Avoid `BigInteger`. Use the field engine (`FieldElement`) for curve ops, or fixed-round word arithmetic for hash/MAC ops.
- Use `cswap` for conditional selection on secret data.
- Compare tags with a bitwise-OR accumulator (no early exit).

## Step 3: Add the expect declaration

Add an `expect object` to `ExpectDeclarations.kt`:

```kotlin
internal expect object Foo {
    fun compute(@Secret key: ByteArray, message: ByteArray): ByteArray
}
```

## Step 4: Implement the native dispatch (actuals)

For each platform source set, add an `actual object` that delegates to the bridge with a pure-K fallback:

```kotlin
// jvmMain / androidMain / iosMain
internal actual object Foo {
    actual fun compute(@Secret key: ByteArray, message: ByteArray): ByteArray =
        fooNative(key, message) ?: FooPureK.compute(key, message)
}
```

Add the `fooNative()` function to the platform's `CryptoBridge.kt`. The bridge file must not contain `@Secret` parameters — the `ConstantTimeRule` must not flag provider-selection branches.

## Step 5: Add the public facade

Add the entry point to either `CryptoFacade.kt` (for a named object like `Authenticator`) or `Crypto.kt` (for the unified `Crypto` object):

```kotlin
public object FooBar {
    public fun foo(key: SecretKey, message: ByteArray): Result<ByteArray> = runCatching {
        Foo.compute(key.bytes, message)
    }
}
```

## Step 6: Add the public CryptoProvider interface method

If the primitive supports native provider injection, add methods to `CryptoProvider` in `CryptoProvider.kt`:

```kotlin
public fun supportsFoo(): Boolean
public fun foo(key: ByteArray, message: ByteArray): ByteArray?
```

## Step 7: Add test vectors

- Place Wycheproof vectors (if available) in `crypto/src/jvmTest/resources/wycheproof/`.
- For primitives without a Wycheproof corpus ([XKCP](https://github.com/XKCP/XKCP) reference), use [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing) known-answer test vectors ([FIPS 202 §D.4/D.5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) for SHAKE128/SHAKE256) or RFC known-answer test vectors as inline test functions. Verify all vectors against a FIPS-compliant reference implementation (e.g. [Python `hashlib`](https://docs.python.org/3/library/hashlib.html)). Each test should have a KDoc comment citing the vector source (e.g. "NIST CAVP KAT, FIPS 202 §D.4").
- Tag tests with `@Tag("positive")` and `@Tag("critical-path")` for correctness vectors. Add `@Tag("timing")` for timing assertions.

Reference: `SHA256Test.kt`, `SHAKE128Test.kt`, `SHAKE256Test.kt`, `X25519Test.kt`, `ChaCha20Poly1305Test.kt`.

## Step 8: Run the gates

```bash
./gradlew check --rerun-tasks --no-build-cache
```

Verify:

- detekt passes (no constant-time violations)
- kover passes (100% on pure-K path)
- abiValidation passes (ABI dump is clean)
- All tests pass

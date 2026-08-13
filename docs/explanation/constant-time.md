# Constant-Time Discipline

> **Explanation.** This page explains why the library is designed to be constant-time and how that guarantee is enforced. For the API, see the [Reference](../reference/api-reference.md). For the architecture, see [Architecture](architecture.md).

## Why constant time matters

A cryptographic implementation is constant-time when its execution time does not depend on secret data. If execution time varies with a secret key, an attacker can measure that variation — through network latency, CPU cache timing, or other side channels — and recover the secret.

This library holds secret key material in its pure-Kotlin path. The native path (JCA, CommonCrypto, Security.framework) is inherited-trust — the OS provider is already assumed constant-time. Therefore, only the pure-Kotlin path is held to the constant-time guarantee.

## What the pure-Kotlin path avoids

The pure-Kotlin implementations avoid two classes of data-dependent behavior:

1. **Data-dependent branches.** Conditional statements (`if`, `when`) whose condition is derived from secret data. Even a single bit of secret-dependent branching can leak information.
2. **Secret-dependent memory access.** Array or collection indexing where the index is derived from secret data. On the JVM, array access timing varies with memory layout. On Kotlin/Native, the indexing can affect cache state.

## What the pure-Kotlin path uses instead

- **Bitwise selection (`cswap`).** The Montgomery ladder in X25519 and Ed25519 uses a conditional swap (`cswap`) built from XOR and a bitmask. The swap either happens or does not, based on a public bit, not a secret value. The operation sequence is always the same.
- **Fixed-round arithmetic.** SHA-256 and SHA-512 use fixed 64-round and 80-round schedules respectively. The round count does not vary with input.
- **Bitwise comparison.** HMAC verification and Ed25519 verification compare all bytes unconditionally using a bitwise OR accumulator. No early exit on first mismatch.
- **Radix-2^26 field arithmetic.** The field engine uses 10 signed `Long` limbs. Values are carried and normalized via fixed shifts and additions. No `BigInteger` is used — `BigInteger` strips leading zeros and runs variable-time arithmetic.

## The `@Secret` annotation

The `@Secret` annotation marks parameters that carry secret data. It is the contract between the implementation and the linter.

```kotlin
internal object X25519PureK {
    fun compute(@Secret scalar: ByteArray, @Secret u: ByteArray): ByteArray
}
```

Only parameters annotated with `@Secret` are treated as secret by the linter. Public data (messages to sign, ciphertexts to verify) does not need the annotation. The salt and info parameters in HKDF are public per RFC 5869 and are not annotated.

## The ConstantTimeRule (static lint)

The `:crypto-detekt-rules` subproject ships a custom detekt rule called `ConstantTimeRule`. It enforces the constant-time discipline at compile time.

### How it works

1. The rule visits each Kotlin file and collects the names of all `@Secret`-annotated parameters.
2. It then scans for `if` expressions, `when` expressions, and array-access expressions.
3. If an `if` or `when` condition text contains a secret parameter name, the rule reports it.
4. If an array access index references a secret parameter name, the rule reports it.

The detection is deliberately **syntactic and file-scoped**. The rule over-approximates — it may flag false positives, which code review resolves. It is designed so that false negatives (missed leaks) are impossible. In a security linter, false positives are preferable to false negatives.

### Why dispatch files are exempt

The `CryptoBridge.kt` files on each platform contain no `@Secret`-annotated parameters. All dispatch branching (provider selection, try-catch, null-elvis fallback) lives there. Because no secret parameter names are in scope, the rule never flags the branching.

The thin `actual` objects (e.g. `jvmMain/.../X25519.kt`) forward `@Secret` parameters directly to native or pure-K paths. They contain no branching over secrets.

### Configuration

The rule is configured in `crypto/detekt.yml`:

```yaml
crypto-constant-time:
  ConstantTimeRule:
    active: true
```

It runs on every source set via detekt (see [ADR-0007](../adr/0007-build-quality-toolchain.md)). The rule is tested in `crypto-detekt-rules/src/test/kotlin/.../ConstantTimeRuleTest.kt`.

## The timing harness (runtime check)

Static analysis alone cannot prove constant-time behavior. The library also includes a Wycheproof-routed timing test harness (see [ADR-0003](../adr/0003-verification-gates.md)).

The `TimingHarness` class measures execution time across varied secret inputs. It asserts that no early exit occurs — comparisons take the same time regardless of how many bytes match. Tests are tagged `@Tag("timing")` and are opt-in via JUnit 5 tag filters (see `crypto/build.gradle.kts`).

## The three verification gates

The pure-Kotlin path must pass three gates (see [ADR-0003](../adr/0003-verification-gates.md)):

1. **Wycheproof test vectors.** Every primitive is checked against Google's Wycheproof corpus. SHA-256 and SHA-512 use RFC 6234 Appendix B known-answer vectors instead (no Wycheproof corpus exists for them).
2. **Static constant-time lint.** The `ConstantTimeRule` bans data-dependent branches and secret-indexed access in secret-data scopes.
3. **Timing harness.** A runtime assertion that no early exit occurs in secret comparisons.

The native-fallback path is inherited-trust. It is not held to the lint, but its presence or absence on each target is covered by the target-matrix tests.

## Per-target considerations

ADR-0003 recommends per-target instrumentation (Android Systrace, iOS Instruments) to confirm constant-time execution on each target. The static lint and timing harness run on the JVM. The cross-target interop harness (`InteropHarnessTest`) ensures the native and pure-K paths produce identical output on every target, catching divergence that could indicate a bug or a timing leak.

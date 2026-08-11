# Fallback strategy: per-primitive, native-or-pure-K

## Status

accepted

## Context

Each target offers a different native crypto surface: JVM/Android expose X25519/Ed25519/ChaCha20-Poly1305/SHA-256 at various API levels (the whole reason for a fallback is older Android / JVM); iOS reaches native crypto through Kotlin/Native interop with CommonCrypto / Security.framework. We keep native acceleration where available. We do not require a pure-Kotlin-only test environment.

## Decision

Substitution is **per-primitive**: each RFC primitive (X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, SHA-256) is independently native-or-pure-K at its call site, gated on whether the target's native provider offers it. On iOS, native primitives come through Kotlin/Native interop with CommonCrypto / Security.framework.

## Consequences

- A target can mix native and pure-K within one algorithm family (e.g. native SHA-256 + pure-K HKDF) without coupling the two implementations.
- Real alternative "all-pure-Kotlin, always" was rejected: it discards available native crypto and widens the constant-time attack surface unnecessarily.
- Per-primitive interop means more native bindings to maintain and test; The verification gates (ADR-0003) mitigate this risk. They keep the pure-K path fully exercised.

## Dispatch architecture

Each platform source set (`jvmMain`, `androidMain`, `iosMain`) contains a
`CryptoBridge.kt` file that holds all native-dispatch branching. This file
has **no `@Secret`-annotated parameters**, so the detekt `ConstantTimeRule`
(ADR-0003) does not flag the provider-selection or try-catch branches. The
actual objects remain minimal: they call the bridge via `elvis` (`?:`) and fall back
to `*PureK` on `null`.

KMP source sets do **not** inherit across targets: `androidMain` does not extend
`jvmMain`. Therefore the bridge and actuals are duplicated per source set. The
JCA code is identical on JVM and Android; the iOS bridge uses CommonCrypto
and Security.framework via Kotlin/Native cinterop.

### HKDF note

No standard JCA HKDF API exists on JVM or Android.
Indeed, `javax.crypto.KDF` is a JDK 25 feature (JEP 510) and is not available
on any Android API level — `KDF.getInstance("HKDF-SHA256")` throws on Android.

HKDF is therefore implemented via the platform HMAC primitive (`javax.crypto.Mac`
on JVM/Android, `CCHmac` on iOS) in `CryptoBridge.kt`, with a PureK
fallback. This matches the approach used by the AndroidX Security Crypto `HKDF`
utility but avoids the dependency. The constant-time lint applies only to the PureK path (ADR-0003).

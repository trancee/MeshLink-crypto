# Fallback strategy: per-primitive, native-or-pure-K

## Status

accepted

## Context

Each target offers a different native crypto surface: JVM/Android expose X25519/Ed25519/ChaCha20-Poly1305/SHA-256 at various API levels (the whole reason for a fallback is older Android / JVM); iOS reaches native crypto through Kotlin/Native interop with CommonCrypto / Security.framework. We want to keep native acceleration where it exists without forcing a pure-Kotlin-only test surface.

## Decision

Substitution is **per-primitive**: each RFC primitive (X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, SHA-256) is independently native-or-pure-K at its call site, gated on whether the target's native provider offers it. On iOS, native primitives come through Kotlin/Native interop with CommonCrypto / Security.framework.

## Consequences

- A target can mix native and pure-K within one algorithm family (e.g. native SHA-256 + pure-K HKDF) without coupling the two implementations.
- Real alternative "all-pure-Kotlin, always" was rejected: it discards available native crypto and widens the constant-time attack surface unnecessarily.
- Per-primitive interop means more native bindings to maintain and test; mitigated by the verification gates (ADR-0003) keeping the pure-K path fully exercised.

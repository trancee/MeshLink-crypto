# Secure storage is out of core scope

## Status

accepted

## Context

The `crypto-kmp` idea lists secure key storage (Android Keystore / iOS Keychain) as a concern. Key *storage* and key *crypto* are distinct seams with different lifecycles, threat models, and cross-target surface area.

## Decision

The core `crypto-kmp` module is **primitives-only**: the six RFC primitives (X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256, SHA-256) plus the per-primitive native fallback. It exposes **no** persistent key-storage API — private/secret keys are never persisted by the library; callers own key bytes, and the library wipes its internal buffers. Secure storage lives in a separate (optional) module or is handled by the consumer.

## Consequences

- Keeps the constant-time / secret-handling surface to the primitives we explicitly scoped, and the cross-target seam surface to one concern.
- Real alternative "store it in the core module" was rejected: it couples two concerns that evolve at different rates and widens the security surface reviewers must audit.
- A future `storage` module (`expect/actual` `SecureStorage` over Android Keystore + DataStore, iOS Keychain via c-interop) can layer on top of the primitives core with its own review cycle.

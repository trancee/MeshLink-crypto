# API surface: typed, no-throw, internal nonce, transparent fallback

## Status

accepted

## Context

The public API is the contract attackers and callers both touch. It must be
hard to misuse (Tink's "hard-to-misuse" goal; signum's no-throw "never discard
results" idiom) and must not leak secrets through timing or memory. The pure-K
path holds secret keys, so the API must make key lifecycle unambiguous.

## Decision

- **Typed key handles**: `PrivateKey`, `PublicKey`, `SecretKey` are small
  `Closeable` types backed by a `ByteArray` that is **zeroed on `close()`** —
  no raw `ByteArray` for key material in the public API.
- **Internal nonce**: `ChaCha20-Poly1305` generates the nonce and returns it
  alongside the ciphertext (nonce-misuse resistant; the caller never supplies
  a nonce — cf. Tink).
- **Transparent fallback**: one API per primitive; native-or-pure-K is selected
  per-primitive (ADR-0002) without caller intervention — callers do not pick a provider.
- **No-throw, `Result`-returning** operations (signum idiom): errors are values,
  not exceptions, so a discarded failed result is visible.
- **Stateless and thread-safe** per primitive (cf. Tink `PRIMITIVES.md`).

## Consequences

- Rejected alternatives: raw `ByteArray` handles (loses lifecycle/wiping),
  caller-supplied nonce (nonce-reuse footgun), and a throwing API (error-handling surprises).
- `Closeable`/zeroing handles add a lifecycle to remember (`use { ... }`); covered as a
  rule in the contributor guide (to be written at `/to-spec`).

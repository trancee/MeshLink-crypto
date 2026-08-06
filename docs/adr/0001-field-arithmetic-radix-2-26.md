# Field arithmetic: radix-2^26, 10 limbs, no BigInteger

## Status

accepted

## Context

X25519 and Ed25519 both operate over the Curve25519 field GF(2^255). The pure-Kotlin path must be constant-time and must not leak secret bit lengths. `BigInteger` strips leading zeros and runs variable-time arithmetic, and data-dependent array indexing leaks on the JVM/LLVM backends — so neither is acceptable in a secret-data path. Algorithm spec texts live in `docs/rfcs/`.

## Decision

Use a 10-limb radix-2^26 representation (2^25.5 bits per limb, 255 bits for the field) with bitwise `cswap` selection and no `BigInteger`. One field engine serves both X25519 and Ed25519. SHA-256, HMAC-SHA256, HKDF, and ChaCha20-Poly1305 use separate word-oriented (32-bit) constant-time arithmetic — they do **not** share the GF(2^255) engine.

## Consequences

- Matches the ref10 reference (X25519, Ed25519) and the a-sit-plus/signum precedent, so the arithmetic is corroborated against a known-good constant-time baseline.
- Radix choice is hard to reverse (pervasive); radix-2^51 (5-limb, as in some Ed25519 engines) was the main alternative and was rejected for divergence from the reference and from the signum baseline we are modelling on.

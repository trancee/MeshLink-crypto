# 07 — Curve25519 field engine (radix-2^26 + cswap, pure-K)

The shared, constant-time field engine for X25519 + Ed25519 (ADR-0001). Prefactoring cut
before the curve primitives.

Status: ready-for-agent

Blocked by: 01, 02

## What to build

- GF(2^255-19) field arithmetic, **10-limb radix-2^26** representation, **no `BigInteger`**.
- **`cswap`** (constant-time conditional swap) for scalar/limb masking.
- Bitwise-only primitive ops; fixed sequence of limb multiplies + carries; no data-dependent branch.
- Common source set only — no platform crypto.

## Acceptance

- [ ] Field multiplication + reduction match known constants (e.g. representation of `2^255 - 19`
      and a sample product checked against a reference).
- [ ] `cswap(a, b, bit)` swaps iff `bit == 1` and swaps neither iff `bit == 0` (table test).
- [ ] `kover` shows 100% coverage on the field arithmetic.
- [ ] `./gradlew detekt` (constant-time rule) is green (no data-dependent branch/index).
- [ ] No `BigInteger`/`java.security` usage in the common field source set.

## Notes

- Consumed by X25519 (08) and EdDSA (09). Cut as a standalone prefactoring ticket so both curve
  primitives are unblocked in parallel without duplicating the engine.

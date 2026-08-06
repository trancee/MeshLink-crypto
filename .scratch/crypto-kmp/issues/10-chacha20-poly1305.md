# 10 — ChaCha20-Poly1305 (pure-K, RFC 8439)

Pure-Kotlin, constant-time AEAD. Its own word arithmetic (mod 2^130-5), not the curve engine.

Status: ready-for-agent

Blocked by: 01, 02

## What to build

- Pure-K `ChaCha20-Poly1305` with an **internal AEAD nonce** (ADR-0005 — the caller does not
  construct/supply the nonce).
- Poly1305 one-time key derivation; GHASH-style 2^130-5 arithmetic; bitwise-only.
- Constant-time MAC + no data-dependent branch on secret/ciphertext data.

## Acceptance

- [ ] RFC 8439 §2.8 (and §2.3.x) test vector: `ciphertext || tag` match exactly.
- [ ] Wycheproof ChaCha20-Poly1305 AEAD vectors pass.
- [ ] `kover` shows 100% coverage on the pure-K path.
- [ ] `./gradlew detekt` (constant-time rule) is green.
- [ ] Internal nonce is not caller-supplied (API review gate).

## Notes

- Independent horizontal slice — can run in parallel with the curve engine (07) and the
  hash primitives (03/04/05/06).

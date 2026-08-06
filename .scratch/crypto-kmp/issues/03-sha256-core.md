# 03 — SHA-256 (pure-K, RFC 6234)

Pure-Kotlin, constant-time SHA-256. The word-arithmetic base reused by the other hash-based
primitives.

Status: ready-for-agent

Blocked by: 01, 02

## What to build

- Pure-K `SHA256` over `ByteArray`/`Int`/`Long` word arithmetic — **no `BigInteger`, no
  `java.security`/`javax`/`BouncyCastle`**, bitwise-only on primitives.
- Constant-time: no data-dependent branch/index on secret input (must pass ticket 02's detekt rule).

## Acceptance

- [ ] RFC 6234 Appendix B test vectors (`abc`, 448-bit `a`×83, 1M `a`) produce the published digests.
- [ ] Wycheproof SHA-256 vectors pass.
- [ ] `kover` shows 100% coverage on the pure-K path.
- [ ] `./gradlew detekt` (constant-time rule) is green on this file.

## Notes

- Tracer bullet for the word-arithmetic idiom; HKDF/HMAC (tickets 05/06) and X25519/EdDSA native
  comparison consume it.

# 09 — EdDSA / Ed25519 (pure-K, RFC 8032)

Pure-Kotlin, constant-time Ed25519 signing/verification over the field engine (07) + SHA-512 (04).

Status: ready-for-agent

Blocked by: 04, 07

## What to build

- Pure-K `Ed25519` — keypair generation, `sign`, `verify` (pure-addition scalar multiplication).
- Internal SHA-512 (ticket 04) feeds the H(R, A, M) reduction; not exported.
- No platform crypto in the common path.

## Acceptance

- [ ] RFC 8032 §7.1 (Ed25519) test vector: secret key → public key + signature over `abc` match.
- [ ] RFC 8032 §7.1 (Ed25519ph/ctx variants) where applicable.
- [ ] Wycheproof "EdDSA" / Ed25519 sig + vrfy vectors pass.
- [ ] `kover` shows 100% coverage on the pure-K path.
- [ ] `./gradlew detekt` (constant-time rule) is green.
- [ ] Signature does NOT expose/use SHA-256 (uses internal SHA-512 only).

## Notes

- Native fallback `actual` wired by ticket 11/12. Blocked specifically on 04 (SHA-512 gap).

# 05 — HMAC-SHA256 (pure-K, RFC 2104)

Pure-Kotlin, constant-time HMAC-SHA256, built on ticket 03's SHA-256.

Status: ready-for-agent

Blocked by: 03

## What to build

- Pure-K `HMAC-SHA256(key, msg)` — **no `javax.crypto`/`java.security`/BouncyCastle**.
- Constant-time key pad handling; no data-dependent branch on secret material.

## Acceptance

- [ ] RFC 2104 §4 test vectors (Key 0x0b, 20-byte key, 100-byte `dd` key, 0x01..0x19 key) match.
- [ ] Wycheproof HMAC-SHA256 vectors pass.
- [ ] `kover` shows 100% coverage on the pure-K path.
- [ ] `./gradlew detekt` (constant-time rule) is green.

## Notes

- Feeds HKDF (06) and the public facade (12).

# 06 — HKDF-SHA256 (pure-K, RFC 5869)

Pure-Kotlin, constant-time HKDF, built on ticket 05's HMAC-SHA256.

Status: ready-for-agent

Blocked by: 03, 05

## What to build

- Pure-K `HKDF-SHA256(ikm, salt, info, len)` — extraction + expansion.
- No platform crypto in `commonMain`.

## Acceptance

- [ ] RFC 5869 §7.1 test vector passes (extract + 42-byte expand).
- [ ] RFC 5869 §7.2 test vector passes (extract + 101-byte expand).
- [ ] Wycheproof HKDF vectors pass.
- [ ] `kover` shows 100% coverage on the pure-K path.

## Notes

- Composes off 03 → 05, so it's cut after HMAC lands.

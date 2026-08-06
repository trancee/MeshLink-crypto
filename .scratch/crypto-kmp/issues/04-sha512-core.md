# 04 — SHA-512 (pure-K, RFC 6234) — internal dependency of Ed25519

⚠️ **Gap found during spec decomposition**: RFC 8032 (Ed25519) *mandates* SHA-512, which is NOT one
of the six exposed primitives. Added as an **internal** dependency (not exposed) so Ed25519 (09) is
unblockable. Reuses the word-arithmetic idiom from ticket 03.

Status: ready-for-agent

Blocked by: 01, 02

## What to build

- Pure-K `SHA512` (64-bit word arithmetic) — **no `BigInteger`/platform crypto**.
- Constant-time (pass ticket 02's detekt rule).
- **Internal only**: not surfaced in the public API (see ADR-0004/ADR-0005); used by EdDSA.

## Acceptance

- [ ] RFC 6234 Appendix B.4/B.5 test vectors produce the published digests.
- [ ] Wycheproof SHA-512 vectors pass.
- [ ] `kover` shows 100% coverage on the pure-K path.
- [ ] `./gradlew detekt` (constant-time rule) is green; SHA-512 is absent from the public API
  symbol list (grep-clean for exported `sha512` entrypoints if API surface should stay at six).

## Notes

- Blocked before 09 (EdDSA). Parallel to 03; both are pure hash cores with no interdependency.

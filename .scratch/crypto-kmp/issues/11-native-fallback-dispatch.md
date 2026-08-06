# 11 — Native fallback dispatch (+ interop harness)

Per-primitive `expect/actual` native-or-pure-K substitution framework (ADR-0002), plus an
interop-equivalence harness that asserts **native result == pure-K result** on each target.

Status: ready-for-agent

Blocked by: 01, 02

## What to build

- `expect` declarations (one per primitive) in `commonMain`: SHA-256, HMAC-SHA256, HKDF-SHA256,
  X25519, Ed25519, ChaCha20-Poly1305.
- `actual` per target:
  - **JVM**: modern `java.security` (`MessageDigest`, `KeyAgreement`, etc.).
  - **Android**: Android KeyStore where hardware-backed is available.
  - **iOS (Darwin)**: CommonCrypto + `Security.framework` via Kotlin/Native interop.
- Policy: native-when-available, else pure-K — **transparent** to the caller.
- **Interop harness**: a test that runs each primitive's pure-K vs native path on identical inputs
  and asserts equality (per-target). This is the "native path covered by target matrix"
  dimension of ADR-0003.
- Native/actual `actual` code is **exempt** from the 100% pure-K coverage gate (inherited trust
  — see ADR-0007).

## Acceptance

- [ ] `./gradlew detekt` is green on the `expect/actual` declarations (common + per-target).
- [ ] Interop-equivalence test exists and runs on JVM + Android + iOS; native == pure-K for each
      available primitive (skipped gracefully where the platform offers none).
- [ ] `kover` excludes `actual` native sources from the pure-K coverage gate.
- [ ] No pure-K code (the `common` arithmetic) is duplicated in `actual`s.

## Notes

- Consumes the internal signatures of 03/05/06/08/09/10 as its comparison oracles — cut after a
  primitive's pure-K impl lands, its `actual` can be completed and interop-checked.

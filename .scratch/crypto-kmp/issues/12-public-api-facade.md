# 12 — Public API facade (hard-to-misuse, ADR-0005)

The typed, stateless, thread-safe, no-throw public surface that every consumer uses; it selects
native-when-available-else-pure-K transparently via ticket 11.

Status: ready-for-agent

Blocked by: 01, 03, 11

## What to build

- **Typed, wiping `Closeable` key handles** — sensitive key material is zeroized on `close()`.
- **No-throw**: public errors surface as `Result<T>`; never exceptions across targets.
- **Internal AEAD nonce** for ChaCha20-Poly1305 (caller never sees/supplies the nonce).
- **Stateless, thread-safe** entry points — primitives are functions over inputs, not sessions.
- **Transparent fallback**: each primitive routes through 11 (native-or-pure-K) without caller
  knowledge; the public API shape is identical in both cases.
- First tracer: `Hasher.sha256(...)` end-to-end (facade → 03 pure-K / 11 native) — demoable
  before the curve/AEAD primitives land.

## Acceptance

- [ ] API compiles on JVM + Android + iOS and is identical across targets.
- [ ] Key handle `close()` wipes secret bytes (verified by a test that reads the backing array after
      `close()` — must be zeroed).
- [ ] Every public entrypoint returns `Result<T>` (no declared `throws`).
- [ ] AEAD nonce is not a public parameter (signature review gate).
- [ ] Interop: facade over native (11) == facade over pure-K, on each target.

## Notes

- Blocked by 03 (first pure-K primitive to wire through the facade) + 11 (native dispatch) + 01.
  Other primitives (05/06/08/09/10) plug into this facade as they land.

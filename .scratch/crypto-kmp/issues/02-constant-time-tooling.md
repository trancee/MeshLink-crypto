# 02 — Constant-time static lint + timing harness

Wire the project's constant-time discipline into the toolchain so every primitive can be linted
and timing-checked (ADR-0003).

Status: ready-for-agent

Blocked by: 01

## What to build

- A **custom detekt rule set** banning data-dependent behavior in secret-data scopes:
  - data-dependent `if`/`when` on secret bytes (branch on secret).
  - data-dependent array indexing on secret indices (secret-dependent memory access).
  - the rule must **allow** constant-time idioms (`cswap`, masked selects, fixed-loop radix arithmetic).
- Mark secret parameters/regions via a lightweight convention (e.g. `@ConstantTime`/param-name
  contract or a `@Secret`-annotated marker) so the rule scopes itself.
- A **Wycheproof-routed timing-variance harness**: a per-target test scaffold (JVM + iOS Darwin) that
  runs a primitive over varied secret inputs and asserts no timing-class divergence (no statistical
  claim — just "runs and records", gating the pure-K path).
- CI: `./gradlew detekt` runs the constant-time rule set on the `common` source set.

## Acceptance

- [ ] The detekt custom rule compiles and **fails the build** on a planted data-dependent `if` over a
      `@Secret` byte; **passes** on `cswap` constant-time code.
- [ ] `timing` test task exists and runs on JVM + iOS targets (no-throw; records samples).
- [ ] `./gradlew detekt` includes the constant-time rule set and is green on ticket 01's scaffold.

## Notes

- Coverage (kover) cannot assert constant-time; this ticket is the *static* + *timing* guard. The
  constant-time *proof* lives in reasoning + these harnesses, not in coverage.
- Reuses the detekt framework that ADR-0007 pins as the lint vehicle.

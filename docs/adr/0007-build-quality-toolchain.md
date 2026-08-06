# Build quality toolchain: ktfmt + detekt + kover, 100% coverage (pure-K path)

## Status

accepted

## Context

The implementation phase needs a repeatable, CI-enforced quality bar: formatting/naming, linting
(including the constant-time discipline from ADR-0003), and coverage. The project requires `ktfmt` for
formatting/naming, `detekt` for static analysis, and `kover` for coverage, at 100% on the pure-K path.

## Decision

- **ktfmt**: code formatting (Google/Java style), run on every target; enforced in CI.
- **detekt**: static analysis + naming rules — and the **vehicle for ADR-0003's constant-time lint**
  (a custom rule set banning data-dependent branching/indexing in secret-data scopes).
- **kover**: code coverage; the **pure-K path must be 100% covered** (CI gate). The native-fallback
  path (inherited-trust) is exempt.
- **CI**: `ktfmt` check + `detekt` + `kover` gate on every PR.

## Consequences

- 100% coverage measures **line execution, not constant-time safety**; the constant-time guarantee is
  argued via the `detekt` lint + reasoning + Wycheproof + the timing harness (ADR-0003), not via coverage.
- Real alternative "no coverage gate / ~80% bar" was rejected: the user scoped 100% on the pure-K path,
  which drives test design (every branch, including error paths, must be exercised).
- `detekt` is also the home for any project-specific naming rules, keeping formatting (ktfmt) and
  naming/lint (detekt) cleanly separated.

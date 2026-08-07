# Agent Workflow

The standard 5-step workflow for every agent task.

## Steps (in order)

1. **Read relevant skill files.** Before implementation, refactors, or any task where an established best practice applies (e.g. testing, security, platform-specific patterns), read the matching `skill://<name>` instructions first.
2. **Prepare commits after each unit of work.** Use Conventional Commits. You MUST ask for explicit user approval before running `git commit` — do not commit autonomously.
3. **Code-review before PR.** Before opening a pull request, run the `/code-review` skill and resolve any genuine issues it finds.
4. **Use `gh` CLI for GitHub operations.** Use `gh` for issues, PRs, repos, and workflow runs — not raw API calls.
5. **Present options on design decisions.** When a design or implementation choice has multiple reasonable approaches (not a routine call covered by an existing rule), present the options and wait for the user's decision instead of picking alone.

## Benchmark regression check (crypto primitives only)

This is the performance half of the ADR-0003 gates. It applies to any change
that touches a pure-K crypto primitive.

- A new or refactored primitive ships a JMH benchmark before the work is done.
  There is no primitive PR without a benchmark. Put it in
  `crypto/src/jvmBenchmark/` and cover the one-shot and incremental paths at
  block-size boundaries.
- A change against a shipped primitive requires a before/after comparison. Run
  `./gradlew :crypto:jvmBenchmarkBenchmark` on the before and on the after.
  Compare mean ns/op and ops/s. A regression of more than 10% on any path blocks
  merge. An improvement of any size is accepted.
- The JVM is not deterministic. Run on a quiet host, not a CI runner. The
  committed benchmark source lets CI replay the comparison at will. CI does not
  gate on it.
- Native-fallback-only changes where the pure-K path is unchanged are exempt
  from the comparison. The benchmark must still exist for the primitive.
- Each new benchmark class is auto-excluded from kover by the wildcard
  `ch.trancee.meshlink.crypto.*Benchmark` (ADR-0009), so the 100% pure-K
  coverage gate stays intact.

See `docs/agents/build.md` for the capture-and-compare procedure. See the
issue-tracker checklist for the per-issue acceptance items.

## Git hooks

The repo keeps hooks in `/.githooks/`. CODEOWNERS protects that directory.
Install them, one time, per clone:

```bash
git config core.hooksPath .githooks
```

`core.hooksPath` is local to the clone. Every contributor runs it once.

### bench-primitive (pre-commit)

The `pre-commit` hook enforces the ADR-0009 benchmark gate in practice. When a
commit stages a file under `crypto/src/commonMain/kotlin/ch/trancee/meshlink/crypto/`,
the hook runs one JMH pass and compares it against the committed baseline
(`crypto/benchmarks/baseline.tsv`). It prints a table of deltas and tags each
benchmark STABLE or NOISY.

This is a surf, not a hard block. The JVM is not deterministic. The baseline is a
single sample on one host. A small delta is noise, not a defect. Record the mean
ns/op in the PR and let review gate the merge (ADR-0009).

After a primitive improvement, or on a new host or JVM, refresh the baseline with
`REFRESH_BASELINE=1 git commit ...`. The hook rewrites `baseline.tsv` from the
current run and stages it.

Skip it with `SKIP_BENCH_HOOK=1 git commit ...`, or `git commit --no-verify`.

### When it fires

Only on staged changes to pure-K primitive sources. Other commits skip the hook
and run instantly.

### Prerequisites

See `CONTRIBUTING.md`. JDK 21, the Android SDK, and a Mac with Xcode are required.

## Skills Used: Completion Report

After completing a task, include a `Skills Used` summary listing which skill instructions you read before starting.

## Agent Guides

For agent-specific conventions, see:

- [Issue tracker](issue-tracker.md) — local markdown issue/spec conventions
- [Triage labels](triage-labels.md) — canonical label strings
- [Domain docs](domain.md) — how to consume this repo's domain documentation

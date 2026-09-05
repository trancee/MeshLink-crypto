# AGENTS

AI execution policy. Before repository mutation: load [`CONSTITUTION.md`](CONSTITUTION.md) fully; summary != source.

```text
R/X/D/O := Constitution notation
priority := CONSTITUTION > AGENTS > scoped docs/ADRs > config/templates/comments
conflict => higher priority + report; lower priority may refine, X weaken
```

## START

1. Load Constitution + task-scope docs/specs/ADRs.
2. Derive commands from repo scripts/metadata/build/CI; X assume stack/layout/framework.
3. Inspect worktree; preserve user/concurrent changes.
4. Map affected contracts/callers/tests/artifacts/platforms/docs/gates.
5. Non-trivial task => short ordered plan, checkable completion, exactly one active implementation step.

START complete iff behavior source-of-truth + proof commands known.

## PATH

- `feature|fix` => TDD: one behavioral test => run expected red => smallest complete implementation => run green => refactor green => repeat. Pre-change pass or setup-failure != red.
- `refactor` => establish green behavior check; preserve observable behavior; migrate all callers; delete obsolete path. Alias/dead path only if Q7 requires deprecation.
- `docs-only` => verify claims against source/config/executable commands; run repo link/markup/spelling/example checks; X unrelated app suite unless docs affect executable/generated content.
- `security|protocol|schema|persistence` => load applicable ADR; update/create O3 ADR; test applicable valid/invalid/incompatible/replayed/truncated/boundary cases.

## ASK

- Unclear requirement/constraint/outcome/material tradeoff OR human-only input => R use `ask` tool.
- Before ask: exhaust repo/docs/config/tools; X ask tool-answerable facts.
- Ask payload R self-contained `{objective,current behavior/state,exact unknown,why it matters,distinct options,each option's cost/risk/compatibility/irreversibility}`.
- O recommendation; if given R identify+justify against known constraints.
- R ask minimum blocking input; finish independent work first.
- X confirmation request when Constitution/docs/local convention determines answer.

## IMPLEMENT

- R existing compliant structure/naming; X parallel convention.
- R root-cause fix; X error suppression/fixture special-case/validation weakening.
- R requested scope; X unrelated cleanup/speculative retry/fallback/config/abstraction.
- Contract change => clean cutover: update all affected callers/platforms/tests/docs/examples/specs/compat records/generated artifacts/release metadata; delete obsolete paths.
- R repository formatter; X manual formatter workaround.
- Generated files => owning command only.
- Materially different compliant product/compat/security/maintenance choices => ASK.

IMPLEMENT complete iff zero repository-controlled consumer needs old behavior.

## VERIFY

1. Run narrow changed behavior/test/program path.
2. Run every applicable broader gate: format/static-analysis/build/test/coverage/security/compat/docs/benchmark/platform.
3. Use clean/forced execution when supported; cache-only != proof.
4. Performance-sensitive => compare committed baseline.
5. Review result against applicable Constitution IDs.

Failure => incomplete; fix cause+rerun. External prerequisite failure => finish reachable work; report exact command/failure/missing prerequisite.

## GIT/EXTERNAL

- R feature branch; X protected-default direct commit.
- Without explicit user approval X commit/push/open-or-merge PR/publish/change external service.
- X discard unrelated work/rewrite history/force-push/destructive cleanup without explicit approval.
- Approved commit => repository format, else Conventional Commits; AI co-author trailer if repository requires.
- R repository-preferred issue/PR/CI integration tool.

## DONE

Yield only if all true:

- request+acceptance criteria complete;
- applicable TDD observed expected red then green;
- affected callers/platforms/docs/examples/specs/compat/generated/release state agree;
- applicable local+CI-equivalent gates pass, or exact external blocker recorded;
- zero temporary/placeholder/disabled/stale/unjustified suppression/`TODO` state;
- Constitution compliant.

Final report R `{changed files+behavior, exact commands+observed results, docs/API/compat/security/performance impact, blocker/unverified state, specialized instructions/skills used}`. X claim unobserved command/test/review/runtime behavior.

## Agent skills

### Issue tracker

Issues and specs live as GitHub issues in `trancee/MeshLink-crypto`. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles, each label string equal to its role name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.

## Domain Context

Read `CONTEXT.md` at the repo root before working in this codebase.

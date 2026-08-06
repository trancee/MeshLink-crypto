# AGENTS

## Project

A Kotlin Multiplatform (KMP) cryptography library: pure-Kotlin, constant-time implementations of RFC-standard primitives, with per-primitive fallback to a target's native crypto provider when available. Spec texts live in `docs/rfcs/`; test vectors come from the Wycheproof corpus.

## Tooling

- **Build**: Gradle with Kotlin DSL (Kotlin 2.4.10). Always invoke `./gradlew` with `--rerun` and `--no-build-cache` — see [docs/agents/build.md](docs/agents/build.md).
- **GitHub**: Use the `gh` CLI for issues, PRs, and workflow runs.
- **Git commits**: Always ask before committing. Prepare Conventional Commits after each unit of work, pending your approval.

## Workflow

Follow the 5-step agent workflow:
1. Read relevant skill files before implementation, refactors, or any task where an established best practice applies.
2. Prepare a Conventional Commit after each unit of work (pending approval — see Git above).
3. Before opening a PR, run the `/code-review` skill and resolve any genuine issues it finds.
4. Use `gh` CLI for GitHub operations.
5. When a design choice has multiple reasonable approaches (not a routine call covered by an existing rule), present the options and wait for your decision.

See [docs/agents/workflow.md](docs/agents/workflow.md) for full details.

## Agent skills

### Issue tracker

Issues and specs live as GitHub issues in `trancee/MeshLink-crypto`. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles, each label string equal to its role name. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.

## Domain Context

Read `CONTEXT.md` at the repo root before working in this codebase.

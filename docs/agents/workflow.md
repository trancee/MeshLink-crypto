# Agent Workflow

The standard 5-step workflow for every agent task.

## Steps (in order)

1. **Read relevant skill files.** Before implementation, refactors, or any task where an established best practice applies (e.g. testing, security, platform-specific patterns), read the matching `skill://<name>` instructions first.
2. **Prepare commits after each unit of work.** Use Conventional Commits. You MUST ask for explicit user approval before running `git commit` — do not commit autonomously.
3. **Code-review before PR.** Before opening a pull request, run the `/code-review` skill and resolve any genuine issues it finds.
4. **Use `gh` CLI for GitHub operations.** Use `gh` for issues, PRs, repos, and workflow runs — not raw API calls.
5. **Present options on design decisions.** When a design or implementation choice has multiple reasonable approaches (not a routine call covered by an existing rule), present the options and wait for the user's decision instead of picking alone.

## Skills Used: Completion Report

After completing a task, include a `Skills Used` summary listing which skill instructions you read before starting.

## Agent Guides

For agent-specific conventions, see:

- [Issue tracker](issue-tracker.md) — local markdown issue/spec conventions
- [Triage labels](triage-labels.md) — canonical label strings
- [Domain docs](domain.md) — how to consume this repo's domain documentation

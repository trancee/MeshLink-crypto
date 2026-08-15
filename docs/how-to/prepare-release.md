# How to: Prepare a Release

> **How-to guide.** This guide walks through preparing, publishing, and verifying a release of MeshLink-crypto to Maven Central. It assumes you are a project maintainer with write access to the repository and the GitHub secrets listed below.

## Prerequisites

### GitHub secrets

The following secrets must be configured in the repository (Settings → Secrets and vars → Actions):

| Secret | Purpose | Format |
|---|---|---|
| `MAVEN_CENTRAL_USERNAME` | Central Portal User Token (not legacy OSSRH token) | Generated at [central.sonatype.com](https://central.sonatype.com/) |
| `MAVEN_CENTRAL_PASSWORD` | Central Portal User Token password | Generated at [central.sonatype.com](https://central.sonatype.com/) |
| `SIGNING_KEY` | ASCII-armored PGP private key block | `gpg --armor --export-secret-keys <KEY_ID>` — entire file including `BEGIN`/`END` headers |
| `SIGNING_KEY_PASSWORD` | Passphrase for the PGP key |  |

> **Do not set `SIGNING_KEY_ID`.** The signing plugin extracts the key ID from the PGP private key block automatically. If `SIGNING_KEY_ID` is set, it is ignored.

See [.env.example](../../.env.example) for a local template.

### Local tools

- JDK 21
- Android SDK (platform 37 + build-tools 37.0.0)
- Git hooks activated: `git config core.hooksPath .githooks`
- `gpg` (for local PGP key export)

## Step 1: Bump the version (if needed)

The library version is pinned in the Gradle version catalog:

```bash
grep "library" gradle/libs.versions.toml
```

To release a new version, update the line:

```toml
library = "0.1.0"  # ← change this
```

Commit with a Conventional Commit:

```bash
git commit -am "chore(release): bump version to 0.2.0"
```

## Step 2: Verify the quality gate locally

Run the full verification suite before tagging:

```bash
./gradlew check --rerun-tasks --no-build-cache
```

This runs:

- **ktfmt** — formatting check
- **detekt** — static analysis (including `ConstantTimeRule`)
- **kover** — 100% coverage gate on the pure-K path
- **abiValidation** — Kotlin ABI dump check
- **Tests** — JVM test suite with Wycheproof + RFC known-answer vectors

All must pass. No shortcuts.

## Step 3: Regenerate the ABI dump (if public API changed)

If you added, removed, or modified public API in `crypto/src/commonMain/`:

```bash
./gradlew :crypto:apiDump --rerun-tasks --no-build-cache
git add crypto/api/crypto.klib.api
git commit -am "chore: regenerate ABI dump for 0.2.0"
```

## Step 4: Update the changelog

Add entries under `## [Unreleased]` → `### Added`, `### Changed`, `### Fixed` sections in [`CHANGELOG.md`](../../CHANGELOG.md). Follow the [Keep a Changelog](https://keepachangelog.com/) format.

## Step 5: Update artifact documentation

If artifact coordinates or API surface changed, update:

- [API reference](../../docs/reference/api-reference.md)
- [Supported primitives table](../../docs/reference/supported-primitives.md)
- [Get started guide](get-started.md) — update version numbers and coordinates

## Step 6: Create and push the release tag

Tags trigger the publish workflow (`.github/workflows/publish.yml`). Tags must match `v*`:

```bash
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

> **Note:** Tag pushes to `main` require `--no-verify` to bypass the pre-push hook (which blocks direct pushes to `main`). Tag pushes bypass git hooks entirely — the pre-push hook does not run for tag-only pushes. The CI `lint` job (run on every push) enforces yamllint, gitleaks, markdownlint, and lychee link checks on all files.

## Step 7: Monitor the publish workflow

The publish workflow runs on `macos-latest` (required for iOS KMP compilation). Watch it at:

```bash
gh run watch --repo trancee/MeshLink-crypto
```

The workflow performs these steps:

1. **Validate PGP signing key** — parses `SIGNING_KEY` via gpg in all formats (raw, with headers, with newline conversion)
2. **Check Sonatype credentials** — verifies Central Portal User Token against the OSSRH Staging API
3. **Drop stale staging repositories** — deletes any leftover "closed" staging repos from prior failed publishes
4. **Build and publish** — `./gradlew :crypto:publish` signs and uploads all publications (JVM, Android, iOS, KMP metadata)
5. **Search for staged repositories** — diagnostic step confirming a staging repo was created
6. **Transfer deployment to Central Portal** — `POST /manual/upload/defaultRepository/ch.trancee.meshlink.crypto` transfers the staged deployment to the Central Portal with the namespace `ch.trancee.meshlink.crypto`.

All steps must pass. If the transfer step fails:

- Check the error response in the workflow logs
- Ensure no stale staging repos exist in the [Central Portal](https://central.sonatype.com/)
- Re-tag and re-push if needed

## Step 8: Verify on Maven Central

After the workflow completes, artifacts typically appear on Maven Central within 10–30 minutes:

```bash
# Check the POM file exists
curl -sI "https://repo1.maven.org/maven2/ch/trancee/meshlink/crypto/meshlink-crypto/0.2.0/meshlink-crypto-0.2.0.pom"

# Check the search index
curl -sS "https://search.maven.org/solrsearch/select?q=g:ch.trancee.meshlink.crypto&rows=20&wt=json"
```

Expected artifacts:

- `ch.trancee.meshlink.crypto:meshlink-crypto` — main metadata (Gradle KMP consumers)
- `ch.trancee.meshlink.crypto:meshlink-crypto-jvm` — JVM (with Javadoc JAR)
- `ch.trancee.meshlink.crypto:meshlink-crypto-android` — Android
- `ch.trancee.meshlink.crypto:meshlink-crypto-ios` — iOS arm64 (KLib)

## Troubleshooting

### "Repository is in state closed and must be dropped"

A previous failed publish left a staging repo in "closed" state. The workflow's "Drop stale staging repositories" step should handle this automatically. If it doesn't, manually drop the repo in the Central Portal UI.

### `402 Payment Required`

Your Sonatype account has been migrated from legacy OSSRH (`s01.oss.sonatype.org`) to the Central Portal. Ensure publishing uses the OSSRH Staging API endpoint (`ossrh-staging-api.central.sonatype.com`), not the legacy URL. Ensure credentials are Central Portal User Tokens, not legacy OSSRH tokens.

### Signing key format errors

The `SIGNING_KEY` secret must be an ASCII-armored PGP private key block. Export it correctly:

```bash
gpg --armor --export-secret-keys <KEY_ID>
```

Copy the entire output, including the `-----BEGIN PGP PRIVATE KEY BLOCK-----` and `-----END PGP PRIVATE KEY BLOCK-----` lines, into the `SIGNING_KEY` secret.

The workflow will try parsing the key as-is, with headers added, and with newline conversion — but a properly exported key should work on the first attempt.

### yamllint failures in CI

The CI `lint` job runs `yamllint` on all YAML files. Lines exceeding 120 characters will fail the build. If you introduce long lines in workflow files, split them across multiple lines using `\` continuation.

### Pre-push hook doesn't run for tag pushes

The pre-push hook validates changed files in a push. Tag-only pushes carry no file diffs (a tag is just a pointer to an existing commit), so the hook's file-change detection finds nothing to validate. The CI `lint` job catches issues that the pre-push hook misses.

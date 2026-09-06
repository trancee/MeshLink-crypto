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
library = "0.1.1"  # ← change this
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

## Step 3: Update ABI baseline (if public API changed)

If you added, removed, or modified public API in `crypto/src/commonMain/`:

```bash
./gradlew :crypto:updateKotlinAbi --rerun-tasks --no-build-cache
git add crypto/api/crypto.klib.api
git commit -m "chore: update ABI baseline for 0.2.0"
```

The build uses KGP's built-in `kotlin { abiValidation {} }` (not the standalone
kx.binary-compatibility-validator plugin). The dump file lives at
`crypto/api/crypto.klib.api` and `abiCheck` is part of the `check` task.

## Step 3b: Verify docs alignment with code

**This MUST pass before every release.** The javadoc JAR bundles hand-written
markdown from `docs/reference/` and `docs/how-to/` alongside Dokka-generated
HTML (ADR-0007). The markdown must reflect the current public API — stale or
missing docs ship to Maven Central consumers.

1. Generate Dokka HTML and the javadoc JAR:

   ```bash
   ./gradlew :crypto:javadocJarJvm --rerun-tasks --no-build-cache
   ```

2. Verify the JAR contains both HTML and markdown:

   ```bash
   jar tf crypto/build/libs/crypto-*-javadoc.jar | grep -c "\.html$"  # ≥ 10
   jar tf crypto/build/libs/crypto-*-javadoc.jar | grep -c "\.md$"     # ≥ 5
   ```

3. Cross-check that every new public API method appears in
   `docs/reference/api-reference.md`:

   ```bash
   # Extract public API from the Dokka HTML and diff against the markdown docs
   # (manual review — spot-check method names in the reference)
   ```

4. Run markdown lint + link check on changed docs:

   ```bash
   npx markdownlint-cli2 "docs/reference/*.md"
   ```

If docs are missing or stale, update `docs/reference/api-reference.md` and
`docs/reference/supported-primitives.md`, then re-run the quality gate.

## Step 4: Update the changelog

Add entries under `## [Unreleased]` → `### Added`, `### Changed`, `### Fixed` sections in [`CHANGELOG.md`](../../CHANGELOG.md). Follow the [Keep a Changelog](https://keepachangelog.com/) format.

## Step 5: Update artifact documentation

If artifact coordinates or API surface changed, update:

- [API reference](../../docs/reference/api-reference.md)
- [Supported primitives table](../../docs/reference/supported-primitives.md)
- [Get started guide](get-started.md) — update version numbers and coordinates

## Automated release script

A repeatable release script is provided at [`../../scripts/release.sh`](../../scripts/release.sh).
It automates version bump, quality gate, ABI update, docs verification,
commit, branch creation, PR, and tagging:

```bash
./scripts/release.sh 0.2.0
```

The script enforces all quality gates before tagging and pushes the tag
to trigger the publish workflow automatically. It creates a feature branch
(never pushes directly to `main`) and opens a PR for review.

## Branch protection

`main` has protected branch rules that **block direct pushes**. Every release
must follow the PR-based flow:

1. Create a release branch: `git checkout -b release/v0.2.0`
2. Push the branch: `git push -u origin release/v0.2.0`
3. Open a PR: `gh pr create --title "release: v0.2.0" --base main`
4. Merge the PR (requires admin/squash if auto-merge is not enabled)
5. Switch to `main` and tag: `git checkout main && git tag -f v0.2.0 && git push origin v0.2.0`

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

1. **Quality gate** — `./gradlew :crypto:check --rerun-tasks --no-build-cache` (detekt + kover + spotless + abiValidation + JVM tests)
2. **Build, sign, and bundle** — `./gradlew :crypto:publish :crypto:centralBundle` publishes all KMP publications (JVM, Android, iOS, KMP metadata) with PGP signatures to a local file repository, then zips into `central-bundle.zip`
3. **Authenticate** — computes a Bearer token from the Central Portal User Token (`base64(USERNAME:PASSWORD)`)
4. **Upload bundle** — `POST https://central.sonatype.com/api/v1/publisher/upload` uploads the zip (skill §3)
5. **Wait for validation** — polls `POST /api/v1/publisher/status?id=$ID` every 10s until the deployment reaches `VALIDATED` or `FAILED` (skill §4)
6. **Publish deployment** — `POST /api/v1/publisher/deployment/$ID` (USER_MANAGED) transitions the deployment to `PUBLISHING → PUBLISHED` (skill §5)
7. **Wait for publication** — polls status until `PUBLISHED`

All steps must pass. If validation fails:

- Check the error response in the workflow logs (missing JARs, invalid POM, or signature issues)
- Fix the issue and re-tag

## Step 8: Verify on Maven Central

After the workflow completes, artifacts typically appear on Maven Central within 10–30 minutes:

```bash
# Check the POM file exists
curl -sI "https://repo1.maven.org/maven2/ch/trancee/meshlink/meshlink-crypto/0.2.0/meshlink-crypto-0.2.0.pom"

# Check the search index
curl -sS "https://search.maven.org/solrsearch/select?q=g:ch.trancee.meshlink&rows=20&wt=json"
```

Expected artifacts:

- `ch.trancee.meshlink:meshlink-crypto` — main metadata (Gradle KMP consumers)
- `ch.trancee.meshlink:meshlink-crypto-jvm` — JVM (with Javadoc JAR + sources JAR)
- `ch.trancee.meshlink:meshlink-crypto-android` — Android (with sources JAR)
- `ch.trancee.meshlink:meshlink-crypto-ios` — iOS arm64 (KLib)

## Troubleshooting

### Missing or empty javadoc JAR

The Central Portal requires a javadoc JAR for JVM publications. The `javadocJarJvm`
task bundles Dokka-generated HTML **and** markdown docs from `docs/reference/` + `docs/how-to/`
into the JAR (ADR-0007). If the JAR is missing or empty:

1. Ensure `javadocJarJvm` is registered and attached to the JVM publication in
   `crypto/build.gradle.kts`:

   ```kotlin
   if (targetName == "jvm") {
       artifact(tasks.named("javadocJarJvm"))
   }
   ```

2. Verify the JAR contains HTML + markdown after building:

   ```bash
   jar tf crypto/build/libs/crypto-*-javadoc.jar | grep -c "\.html$"  # ≥ 10
   jar tf crypto/build/libs/crypto-*-javadoc.jar | grep -c "\.md$"     # ≥ 5
   ```

3. Check `.dokka/` HTML output exists: `./gradlew :crypto:dokkaGenerateHtml`

### Missing sources JAR

The Central Portal requires a sources JAR for all publications. Ensure `sourcesJarJvm` and `sourcesJarAndroid` tasks are wired into the respective publications in `crypto/build.gradle.kts`.

### Upload returns non-201 status

Ensure `MAVEN_CENTRAL_USERNAME` and `MAVEN_CENTRAL_PASSWORD` are Central Portal User Tokens (not legacy OSSRH tokens). Generate at [central.sonatype.com/publishing/user-tokens](https://central.sonatype.com/publishing/user-tokens).

### Signing key not recognized

The `SIGNING_KEY` secret must be an ASCII-armored PGP private key block. The workflow passes it as `ORG_GRADLE_PROJECT_signingInMemoryKey` — the Gradle signing plugin reads it directly, no normalization needed. Export with:

```bash
gpg --armor --export-secret-keys <KEY_ID>
```

Copy the entire output (including `BEGIN`/`END` headers) into the `SIGNING_KEY` GitHub secret.

### yamllint failures in CI

The CI `lint` job runs `yamllint` on all YAML files. Lines exceeding 120 characters will fail the build. If you introduce long lines in workflow files, split them across multiple lines using `\` continuation.

### Pre-push hook doesn't run for tag pushes

The pre-push hook validates changed files in a push. Tag-only pushes carry no file diffs (a tag is just a pointer to an existing commit), so the hook's file-change detection finds nothing to validate. The CI `lint` job catches issues that the pre-push hook misses.

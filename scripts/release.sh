#!/usr/bin/env bash
#
# Automated, repeatable release script for MeshLink-crypto.
#
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 0.1.1
#
# This script:
#   1. Bumps the version in gradle/libs.versions.toml
#   2. Runs the full quality gate (detekt + kover + spotless + abiValidation + tests)
#   3. Updates the ABI baseline via apiDump
#   4. Verifies API docs alignment (javadoc JAR contains HTML + markdown)
#   5. Commits changes on a release branch
#   6. Opens a PR (if branch is not main)
#   7. Tags and pushes the tag to trigger the publish workflow
#
# All ./gradlew invocations include --rerun-tasks --no-build-cache per ADR-0007.

set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>"
  echo "Example: $0 0.1.1"
  exit 1
fi

BRANCH="release/v${VERSION}"
TAG="v${VERSION}"

echo "=== Release: ${VERSION} ==="

# --- Step 1: Version bump ---
echo "[1/7] Bumping version to ${VERSION}..."
sed -i.bak "s/^library = \".*\"/library = \"${VERSION}\"/" gradle/libs.versions.toml
rm -f gradle/libs.versions.toml.bak

# --- Step 2: Quality gate ---
echo "[2/7] Running quality gate..."
./gradlew :crypto:check --rerun-tasks --no-build-cache

# --- Step 3: ABI baseline update ---
echo "[3/7] Updating ABI baseline..."
./gradlew :crypto:updateKotlinAbi --rerun-tasks --no-build-cache

# --- Step 4: Docs verification ---
echo "[4/7] Verifying docs alignment..."
./gradlew :crypto:javadocJarJvm :crypto:apiDump --rerun-tasks --no-build-cache

# Verify javadoc JAR exists and contains HTML docs
JAR_FILE="crypto/build/libs/crypto-${VERSION}-javadoc.jar"
if [[ ! -f "$JAR_FILE" ]]; then
  echo "ERROR: javadoc JAR not found at $JAR_FILE"
  exit 1
fi

HTML_COUNT=$(jar tf "$JAR_FILE" | grep -c "\.html$" || true)
MD_COUNT=$(jar tf "$JAR_FILE" | grep -c "\.md$" || true)
if [[ "$HTML_COUNT" -lt 10 ]]; then
  echo "ERROR: javadoc JAR has too few HTML files ($HTML_COUNT) — Javadoc is empty"
  exit 1
fi
if [[ "$MD_COUNT" -lt 5 ]]; then
  echo "ERROR: javadoc JAR has too few markdown files ($MD_COUNT) — docs/reference not bundled"
  exit 1
fi
echo "  javadoc JAR: ${HTML_COUNT} HTML + ${MD_COUNT} MD files"

# --- Step 5: Commit ---
echo "[5/7] Committing release..."
git add -A
if git diff --cached --quiet; then
  echo "  No changes to commit (version may already be set)"
else
  git commit -m "release: v${VERSION}"
fi

# --- Step 6: Branch + PR ---
echo "[6/7] Creating branch ${BRANCH}..."
git checkout -b "$BRANCH" 2>/dev/null || git checkout "$BRANCH"
git push -u origin "$BRANCH" 2>/dev/null || true

# Open PR if gh is available and branch is not main
if command -v gh &>/dev/null; then
  if git branch --show-current | grep -q "$BRANCH"; then
    gh pr create \
      --title "release: v${VERSION}" \
      --body "Automated release for v${VERSION}" \
      --head "$BRANCH" \
      --base main \
      2>/dev/null || echo "  PR creation skipped (may already exist)"
  fi
fi

# --- Step 7: Tag ---
echo "[7/7] Tagging v${VERSION}..."
git tag -f "$TAG"
git push origin "$TAG"

echo ""
echo "=== Release ${VERSION} complete ==="
echo "Tag pushed. The publish workflow will trigger automatically."
echo "Monitor: https://github.com/trancee/MeshLink-crypto/actions"

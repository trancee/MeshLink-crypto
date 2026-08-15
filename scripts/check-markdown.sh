#!/usr/bin/env bash
# Checks Markdown files for style/syntax correctness (markdownlint-cli2)
# and broken links (lychee): internal file/anchor links always, external
# URLs unless --offline is given.
#
# See docs/how-to/run-checks.md for prerequisites.
#
# Usage: ./scripts/check-markdown.sh [--offline] [file ...]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

offline=0
files=()
for arg in "$@"; do
  if [[ "$arg" == "--offline" ]]; then
    offline=1
  else
    files+=("$arg")
  fi
done

if ! command -v npx >/dev/null 2>&1; then
  echo "[check-markdown] npx (Node.js) is required for markdownlint-cli2." >&2
  echo "[check-markdown] Install Node.js, or see docs/how-to/run-checks.md." >&2
  exit 1
fi

if ! command -v lychee >/dev/null 2>&1; then
  echo "[check-markdown] lychee is required for link checking." >&2
  echo "[check-markdown] Install it with: brew install lychee (or run" >&2
  echo "[check-markdown] ./scripts/check-markdown.sh)." >&2
  exit 1
fi

if [[ ${#files[@]} -eq 0 ]]; then
  files=("**/*.md")
fi

echo "[check-markdown] Running markdownlint-cli2: ${files[*]}"
npx --yes markdownlint-cli2 "${files[@]}"

lychee_args=(--no-progress "${files[@]}")
if [[ "$offline" -eq 1 ]]; then
  lychee_args+=(--offline)
  echo "[check-markdown] Running lychee (offline — internal links only): ${files[*]}"
else
  echo "[check-markdown] Running lychee (internal + external links): ${files[*]}"
fi
lychee "${lychee_args[@]}"

echo "[check-markdown] OK"

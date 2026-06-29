#!/usr/bin/env bash
# Create a GitHub release with virlink (linux amd64) + setup.sh assets.
# Publishes to the public install repo (no source code).
# Usage: ./scripts/release.sh v2.9.4 "Release notes here"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
GITHUB_REPO="hosseinpv1379/virtlink"

VERSION="${1:?Usage: $0 vX.Y.Z [release notes]}"
NOTES="${2:-Release ${VERSION}}"

TAG="${VERSION#v}"
if ! grep -q "const version = \"${TAG}\"" internal/app/cli.go; then
  echo "error: internal/app/cli.go version does not match ${TAG}" >&2
  exit 1
fi

echo "→ Building linux/amd64 virlink..."
make linux

for asset in virlink scripts/setup.sh; do
  [[ -f "$asset" ]] || { echo "error: missing $asset" >&2; exit 1; }
done

echo "→ Creating GitHub release ${VERSION}..."
gh release create "$VERSION" \
  --repo "$GITHUB_REPO" \
  --title "$VERSION" \
  --notes "$NOTES" \
  virlink \
  scripts/setup.sh#setup.sh

echo "✓ https://github.com/${GITHUB_REPO}/releases/tag/${VERSION}"

sync_setup_to_main() {
  local git_root setup_src wt
  git_root="$(git -C "$ROOT" rev-parse --show-toplevel)"
  setup_src="$ROOT/scripts/setup.sh"
  wt="$(mktemp -d "${TMPDIR:-/tmp}/virtlink-main.XXXXXX")"

  echo "→ Syncing setup.sh to main branch (public install repo, no source)..."
  git -C "$git_root" fetch origin main
  git -C "$git_root" worktree add -B main "$wt" origin/main
  cp "$setup_src" "$wt/setup.sh"
  chmod +x "$wt/setup.sh"
  if git -C "$wt" diff --quiet setup.sh; then
    echo "  main/setup.sh already up to date"
  else
    git -C "$wt" add setup.sh
    git -C "$wt" commit -m "sync setup.sh from release ${VERSION}"
    git -C "$wt" push origin main
    echo "  ✓ main/setup.sh updated"
  fi
  git -C "$git_root" worktree remove "$wt" --force
}

sync_setup_to_main

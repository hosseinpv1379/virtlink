#!/usr/bin/env bash
# Create a GitHub release with virlink (linux amd64) + setup.sh assets.
# Publishes to the public install repo (no source code).
# Usage: ./scripts/release.sh v2.9.4 "Release notes here"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
GITHUB_REPO="hosseinpv1379/virtlink-install"

VERSION="${1:?Usage: $0 vX.Y.Z [release notes]}"
NOTES="${2:-Release ${VERSION}}"

TAG="${VERSION#v}"
if ! grep -q "const version = \"${TAG}\"" internal/virlink/cli.go; then
  echo "error: internal/virlink/cli.go version does not match ${TAG}" >&2
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

#!/usr/bin/env bash
# Create a GitHub release with virlink (linux amd64) + setup.sh assets.
# Usage: ./release.sh v2.9.0 "Release notes here"
set -euo pipefail

cd "$(dirname "$0")"
GITHUB_REPO="hosseinpv1379/virtlink"

VERSION="${1:?Usage: $0 vX.Y.Z [release notes]}"
NOTES="${2:-Release ${VERSION}}"

TAG="${VERSION#v}"
if ! grep -q "const version = \"${TAG}\"" main.go; then
  echo "error: main.go version does not match ${TAG}" >&2
  exit 1
fi

echo "→ Building linux/amd64 virlink..."
make linux

for asset in virlink setup.sh; do
  [[ -f "$asset" ]] || { echo "error: missing $asset" >&2; exit 1; }
done

echo "→ Creating GitHub release ${VERSION}..."
gh release create "$VERSION" \
  --repo "$GITHUB_REPO" \
  --title "$VERSION" \
  --notes "$NOTES" \
  virlink setup.sh

echo "✓ https://github.com/${GITHUB_REPO}/releases/tag/${VERSION}"

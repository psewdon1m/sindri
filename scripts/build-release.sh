#!/usr/bin/env bash
set -euo pipefail

version="${1:?version is required}"
output="${2:-release-artifacts}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || exit 2
mkdir -p "$root/$output"
make -C "$root" clean deb VERSION="$version" BUILD_ID="${GITHUB_SHA:-local}"
cp "$root/dist/sindri_${version}_amd64.deb" "$root/$output/"
(
  cd "$root/$output"
  sha256sum "sindri_${version}_amd64.deb" > "sindri_${version}_amd64.deb.sha256"
)
installer_sha="$(sha256sum "$root/install.sh" | awk '{print $1}')"
package_sha="$(sha256sum "$root/dist/sindri_${version}_amd64.deb" | awk '{print $1}')"
jq \
  --arg version "$version" \
  --arg repository_url "https://github.com/${repository}" \
  --arg ref "sindri-v${version}" \
  --arg installer_url "https://raw.githubusercontent.com/${repository}/sindri-v${version}/install.sh" \
  --arg installer_sha "$installer_sha" \
  --arg package_url "https://github.com/${repository}/releases/download/sindri-v${version}/sindri_${version}_amd64.deb" \
  --arg package_sha "$package_sha" \
  '.version = $version | .repository.url = $repository_url | .repository.ref = $ref | .repository.path = "." | .installer.url = $installer_url | .installer.sha256 = $installer_sha | .package.url = $package_url | .package.sha256 = $package_sha' \
  "$root/sindri-release-manifest.json" > "$root/$output/sindri-release-manifest.json"

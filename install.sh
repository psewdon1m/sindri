#!/usr/bin/env sh
set -eu

ACTION="${1:-install}"
ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)
VERSION="${VERSION:-1.0.0-dev}"
DEFAULT_MANIFEST_URL="https://github.com/psewdon1m/sindri/releases/download/sindri-current/sindri-release-manifest.json"

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "Sindri installation must run as root." >&2; exit 4; }
}

validate_ubuntu() {
  [ -r /etc/os-release ] || { echo "Cannot identify operating system." >&2; exit 3; }
  # shellcheck disable=SC1091
  . /etc/os-release
  [ "${ID:-}" = "ubuntu" ] || { echo "Unsupported operating system: ${PRETTY_NAME:-unknown}" >&2; exit 3; }
  case "${VERSION_ID:-}" in 22.04|24.04|26.04) ;; *) echo "Unsupported Ubuntu version: ${VERSION_ID:-unknown}" >&2; exit 3 ;; esac
  [ "$(uname -m)" = "x86_64" ] || { echo "Sindri currently supports amd64 only." >&2; exit 3; }
}

bootstrap_source() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git python3
  manifest_url="${SINDRI_MANIFEST_URL:-$DEFAULT_MANIFEST_URL}"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT TERM
  manifest="$tmp/manifest.json"
  curl -fL --retry 2 --connect-timeout 10 "$manifest_url" -o "$manifest"
  fields=$(python3 - "$manifest" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
repository = manifest.get("repository") or {}
installer = manifest.get("installer") or {}
if manifest.get("schema_version") != 1 or manifest.get("product") != "sindri":
    raise SystemExit("Downloaded Sindri release manifest is invalid.")
url = repository.get("url")
ref = repository.get("ref") or "main"
path = repository.get("path")
installer_sha256 = str(installer.get("sha256") or "").removeprefix("sha256:").lower()
if (
    not isinstance(url, str)
    or not url.startswith("https://")
    or not isinstance(path, str)
    or not path
    or len(installer_sha256) != 64
    or any(character not in "0123456789abcdef" for character in installer_sha256)
):
    raise SystemExit("Sindri release manifest has no valid repository coordinates.")
print(url)
print(ref)
print(path)
print(manifest.get("version"))
print(installer_sha256)
PY
)
  repository_url=$(printf '%s\n' "$fields" | sed -n '1p')
  repository_ref=$(printf '%s\n' "$fields" | sed -n '2p')
  repository_path=$(printf '%s\n' "$fields" | sed -n '3p')
  VERSION=$(printf '%s\n' "$fields" | sed -n '4p')
  installer_sha256=$(printf '%s\n' "$fields" | sed -n '5p')
  export VERSION
  git clone --depth 1 --branch "$repository_ref" "$repository_url" "$tmp/source"
  source_dir="$tmp/source/$repository_path"
  [ -f "$source_dir/go.mod" ] || { echo "Downloaded Sindri repository is invalid." >&2; exit 14; }
  actual_installer_sha256=$(sha256sum "$source_dir/install.sh" | awk '{print $1}')
  [ "$actual_installer_sha256" = "$installer_sha256" ] || {
    echo "Downloaded Sindri installer checksum does not match the release manifest." >&2
    exit 14
  }
  exec sh "$source_dir/install.sh" "$ACTION"
}

case "$ACTION" in
  install|update|repair)
    require_root
    validate_ubuntu
    if [ ! -f "$ROOT_DIR/go.mod" ]; then bootstrap_source; fi
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl golang-go make
    make -C "$ROOT_DIR" deb VERSION="$VERSION"
    package=$(find "$ROOT_DIR/dist" -maxdepth 1 -name 'sindri_*_amd64.deb' | sort | tail -n 1)
    [ -n "$package" ] || { echo "Sindri package was not built." >&2; exit 14; }
    dpkg -i "$package"
    /usr/bin/sindri init
    ;;
  status)
    if command -v sindri >/dev/null 2>&1; then
      sindri version
    else
      echo "Sindri is not installed"
      exit 1
    fi
    ;;
  *)
    echo "Usage: install.sh install|update|repair|status" >&2
    exit 2
    ;;
esac

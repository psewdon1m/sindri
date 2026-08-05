#!/usr/bin/env sh
set -eu

ACTION="${1:-install}"
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

download_package() {
  temporary=$1
  manifest="$temporary/manifest.json"
  curl -fsSL --retry 3 --connect-timeout 10 "${SINDRI_MANIFEST_URL:-$DEFAULT_MANIFEST_URL}" -o "$manifest"
  fields=$(python3 - "$manifest" <<'PY'
import json, re, sys
from urllib.parse import urlparse
with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
package = manifest.get("package") or {}
version = str(manifest.get("version") or "")
url = str(package.get("url") or "")
checksum = str(package.get("sha256") or "").removeprefix("sha256:").lower()
if manifest.get("schema_version") != 1 or manifest.get("product") != "sindri":
    raise SystemExit("Downloaded Sindri release manifest is invalid.")
if not re.fullmatch(r"\d+\.\d+\.\d+", version):
    raise SystemExit("Downloaded Sindri release version is invalid.")
if urlparse(url).scheme != "https" or urlparse(url).hostname != "github.com":
    raise SystemExit("Sindri package must be downloaded from GitHub over HTTPS.")
if not re.fullmatch(r"[a-f0-9]{64}", checksum):
    raise SystemExit("Downloaded Sindri package checksum is invalid.")
print(version)
print(url)
print(checksum)
PY
)
  package_url=$(printf '%s\n' "$fields" | sed -n '2p')
  package_sha=$(printf '%s\n' "$fields" | sed -n '3p')
  package_path="$temporary/sindri.deb"
  curl -fsSL --retry 3 --connect-timeout 10 "$package_url" -o "$package_path"
  printf '%s  %s\n' "$package_sha" "$package_path" | sha256sum -c - >/dev/null
  printf '%s' "$package_path"
}

install_sindri() {
  require_root
  validate_ubuntu
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl python3
  temporary=$(mktemp -d)
  trap 'rm -rf "$temporary"' EXIT INT TERM
  package=$(download_package "$temporary")
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"
  /usr/bin/sindri init
  /usr/bin/sindri version
}

case "$ACTION" in
  install|update|repair) install_sindri ;;
  status)
    if command -v sindri >/dev/null 2>&1; then
      sindri version
    else
      echo "Sindri is not installed"
      exit 1
    fi
    ;;
  help|--help|-h) echo "Usage: install.sh install|update|repair|status" ;;
  *) echo "Unknown Sindri installer action: $ACTION" >&2; exit 2 ;;
esac

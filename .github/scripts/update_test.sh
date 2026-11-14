#!/usr/bin/env bash
# Updates the previous release to the latest one, the way installed wallets do it on this system,
# against the real GitHub releases and APT repository (.github/workflows/updates.yml):
#   .github/scripts/update_test.sh PREVIOUS LATEST        e.g. 0.13.0 0.13.1
# - AppImage: the previous one asks GitHub, downloads the latest, checks its signature and replaces
#   itself ('cli update', as the window does once a day);
# - .deb: the previous one is installed and updated through its APT repository, with the package's
#   own updater when it has one (0.13.2 onwards), as Settings -> About -> Update does.
# Runs as root or with sudo; needs curl and apt. Works in a container too.
set -euo pipefail
previous="$1" latest="$2"
SUDO=""; [[ "$(id -u)" == 0 ]] || SUDO=sudo
BASE="https://github.com/CitComAI-Hub/atesta-id-wallet/releases/download"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
version_of() { "$@" --version | awk '{print $2}'; }

# Files of the previous release, checked against its SHA256SUMS.
appimage="Atesta_ID_Wallet-$previous-x86_64.AppImage" deb="atesta-id-wallet_${previous}_amd64.deb"
for file in SHA256SUMS "$appimage" "$deb"; do
    curl -fsSLO --retry 3 "$BASE/v$previous/$file"
done
sha256sum -c SHA256SUMS --ignore-missing --strict

echo "== AppImage $previous -> $latest"
export APPIMAGE_EXTRACT_AND_RUN=1 ATESTA_ID_WALLET_HOME="$WORK/home"
chmod +x "$appimage"
[[ "$(version_of "./$appimage" cli)" == "$previous" ]]
# GitHub allows 60 anonymous API requests per hour per address, shared by the runners: retried.
for attempt in 1 2 3; do
    "./$appimage" cli update && break
    [[ $attempt == 3 ]] && exit 1
    sleep 60
done
found="$(version_of "./$appimage" cli)"
[[ "$found" == "$latest" ]] || { echo "The AppImage is $found after updating, not $latest"; exit 1; }
echo "✔ AppImage updated itself to $found"

echo "== .deb $previous -> $latest"
$SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --install-recommends "./$deb" >/dev/null
[[ "$(dpkg-query -W -f='${Version}' atesta-id-wallet)" == "$previous" ]]
# GitHub Pages may take a moment to serve the repository that was just deployed.
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -x /usr/libexec/atesta-id-wallet/update ]]; then
        how="its updater"
        $SUDO /usr/libexec/atesta-id-wallet/update >/dev/null
    else
        how="apt"
        $SUDO apt-get update -q >/dev/null
        $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --only-upgrade atesta-id-wallet >/dev/null
    fi
    found="$(dpkg-query -W -f='${Version}' atesta-id-wallet)"
    [[ "$found" == "$latest" ]] && break
    [[ $attempt == 10 ]] && { echo "The .deb is $found after updating with $how, not $latest"; exit 1; }
    sleep 30
done
echo "✔ .deb updated to $found with $how"
"/opt/atesta-id-wallet/atesta-id-wallet" --version
$SUDO apt-get purge -y -q atesta-id-wallet >/dev/null

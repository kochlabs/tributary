#!/usr/bin/env bash
# Installs or upgrades Tributary on Debian/Ubuntu from its .deb package.
# The package depends on clickhouse-server, which Debian doesn't ship, so this
# adds the ClickHouse apt repository first.
#
#   sudo deploy/install.sh                     # newest dist/tributary_*.deb
#   sudo deploy/install.sh tributary_X_amd64.deb
set -euo pipefail
cd "$(dirname "$0")/.."

[[ $EUID -eq 0 ]] || { echo "run as root (sudo $0)"; exit 1; }

DEB=${1:-$(ls -t dist/tributary_*_amd64.deb 2>/dev/null | head -1 || true)}
[[ -n $DEB && -f $DEB ]] || { echo "no package found: run 'make deb' or pass the .deb path"; exit 1; }

if [[ ! -f /etc/apt/sources.list.d/clickhouse.list ]]; then
  echo "==> adding the ClickHouse apt repository"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg
  curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb lts main" > /etc/apt/sources.list.d/clickhouse.list
  apt-get update -qq
fi

echo "==> installing $DEB"
# ClickHouse would otherwise prompt for a default-user password; it only
# listens on localhost and Tributary uses its own credentials.
DEBIAN_FRONTEND=noninteractive CLICKHOUSE_PASSWORD='' apt-get install -y "$(realpath "$DEB")"
echo "Point flow exporters at UDP 2055 (NetFlow), 4739 (IPFIX) or 6343 (sFlow)."

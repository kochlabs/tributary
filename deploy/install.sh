#!/usr/bin/env bash
# Installs Tributary on Debian/Ubuntu: ClickHouse, the nfad
# service, kernel tuning and a dedicated service account. Re-runnable.
set -euo pipefail
cd "$(dirname "$0")/.."

[[ $EUID -eq 0 ]] || { echo "run as root (sudo $0)"; exit 1; }
[[ -x bin/nfad ]] || { echo "bin/nfad missing: run 'make' first"; exit 1; }

echo "==> ClickHouse"
if ! command -v clickhouse-server >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq apt-transport-https ca-certificates curl gnupg
  curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb lts main" > /etc/apt/sources.list.d/clickhouse.list
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive CLICKHOUSE_PASSWORD='' apt-get install -y -qq clickhouse-server clickhouse-client
fi
install -m 644 deploy/clickhouse/netflow-appliance.xml /etc/clickhouse-server/config.d/
mkdir -p /etc/netflow
if [[ ! -s /etc/netflow/clickhouse.pw ]]; then
  openssl rand -hex 16 > /etc/netflow/clickhouse.pw
fi
HASH=$(tr -d '\n' < /etc/netflow/clickhouse.pw | sha256sum | cut -d' ' -f1)
sed "s/@PASSWORD_SHA256@/$HASH/" deploy/clickhouse/users-netflow.xml.tmpl > /etc/clickhouse-server/users.d/netflow.xml
systemctl enable clickhouse-server >/dev/null
systemctl restart clickhouse-server

echo "==> service account and files"
id nfa >/dev/null 2>&1 || useradd --system --home /var/lib/nfa --shell /usr/sbin/nologin nfa
install -d -o nfa -g nfa -m 750 /var/lib/nfa
chgrp nfa /etc/netflow/clickhouse.pw && chmod 640 /etc/netflow/clickhouse.pw
install -m 755 bin/nfad /usr/local/bin/nfad
install -m 755 bin/flowgen /usr/local/bin/nfa-flowgen
install -m 644 deploy/99-nfa.conf /etc/sysctl.d/99-nfa.conf
sysctl -q --system
install -m 644 deploy/nfad.service /etc/systemd/system/nfad.service

echo "==> admin helper (updates, time, services)"
# Remove the earlier updates-only helper if present.
systemctl disable --now tributary-update.path >/dev/null 2>&1 || true
rm -f /etc/systemd/system/tributary-update.path /etc/systemd/system/tributary-update.service \
  /usr/local/lib/tributary/tributary-update.sh
rm -rf /var/lib/nfa/update-request /var/lib/tributary-update
install -d -m 755 /usr/local/lib/tributary
install -m 755 deploy/admin/tributary-admin.sh /usr/local/lib/tributary/
install -m 644 deploy/admin/services.conf /usr/local/lib/tributary/
install -d -o nfa -g nfa -m 750 /var/lib/nfa/admin-request
install -d -o root -g nfa -m 750 /var/lib/tributary-admin
for u in tributary-admin.path tributary-admin.service tributary-update-check.service tributary-update-check.timer; do
  install -m 644 deploy/admin/$u /etc/systemd/system/
done
command -v jq >/dev/null || apt-get install -y -qq jq
systemctl daemon-reload
systemctl enable nfad >/dev/null
systemctl enable --now tributary-admin.path tributary-update-check.timer >/dev/null
systemctl restart nfad

echo "==> waiting for the service"
for _ in $(seq 30); do
  curl -sfk https://localhost/healthz >/dev/null && break
  sleep 1
done
echo
echo "Tributary is running: https://$(hostname -I | awk '{print $1}')/"
if [[ -f /var/lib/nfa/initial-admin-password ]]; then
  echo "Initial login: admin / $(cat /var/lib/nfa/initial-admin-password)"
  echo "(change it after signing in, then delete /var/lib/nfa/initial-admin-password)"
fi
echo "Point flow exporters at UDP 2055 (NetFlow), 4739 (IPFIX) or 6343 (sFlow)."

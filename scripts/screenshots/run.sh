#!/usr/bin/env bash
# Retakes docs/screenshots from an isolated demo instance: its own ClickHouse,
# nfad on 127.0.0.1:8443 and 24 hours of simulated traffic, all in a
# temporary directory that is removed afterwards. It never touches a running
# appliance, and refuses to start if one of its ports is in use.
#
# Needs: clickhouse, go, node and Chromium (CHROME=/path/to/chrome otherwise).
# GeoIP and MAC vendor data are copied from the appliance's data directory
# (DATA_DIR, default /var/lib/nfa; read with sudo if needed) so the shots
# show countries, organizations and vendors.
#
#   scripts/screenshots/run.sh        (or: make screenshots)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
DATA_DIR=${DATA_DIR:-/var/lib/nfa}
OUT=${OUT:-$ROOT/docs/screenshots}
HISTORY=${HISTORY:-24h}
PORTS="8443 8080 19000 18123 12055 14739 16343"

die() { echo "screenshots: $*" >&2; exit 1; }
for c in clickhouse go node; do command -v $c >/dev/null || die "needs $c"; done
CHROME=${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)}
[[ -n $CHROME ]] || die "needs Chromium: set CHROME=/path/to/chrome"
for p in $PORTS; do
  ss -Htln "sport = :$p" | grep -q . && die "port $p is in use"
done

W=$(mktemp -d -t tributary-shots.XXXXXX)
pids=()
cleanup() {
  touch "$W/stop"
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT

echo "==> building"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$W/nfad" ./cmd/nfad && go build -o "$W/flowgen" ./cmd/flowgen)
(cd "$HERE" && npm ci --silent --no-audit --no-fund)

echo "==> starting ClickHouse"
mkdir -p "$W"/ch/{data,tmp,files,log} "$W"/nfa/{geoip,oui}
cat > "$W/ch/config.xml" <<XML
<clickhouse>
  <logger><level>warning</level><log>$W/ch/log/server.log</log><errorlog>$W/ch/log/error.log</errorlog></logger>
  <listen_host>127.0.0.1</listen_host><tcp_port>19000</tcp_port><http_port>18123</http_port>
  <path>$W/ch/data/</path><tmp_path>$W/ch/tmp/</tmp_path><user_files_path>$W/ch/files/</user_files_path>
  <max_server_memory_usage>1600000000</max_server_memory_usage><memory_worker_dynamic_hard_limit>0</memory_worker_dynamic_hard_limit>
  <mark_cache_size>134217728</mark_cache_size><uncompressed_cache_size>0</uncompressed_cache_size>
  <users><default><password></password><networks><ip>127.0.0.1</ip></networks><profile>default</profile><quota>default</quota></default></users>
  <profiles><default><max_memory_usage>1200000000</max_memory_usage></default></profiles><quotas><default></default></quotas>
</clickhouse>
XML
(cd "$W/ch" && exec clickhouse server --config-file="$W/ch/config.xml" > "$W/ch/log/stdout.log" 2>&1) &
pids+=($!)
until clickhouse client --port 19000 -q 'SELECT 1' >/dev/null 2>&1; do sleep 1; done

# GeoIP and vendor data, so the shots show countries, organizations and vendors.
copy() { cat "$1" > "$2" 2>/dev/null || sudo -n cat "$1" > "$2" 2>/dev/null || rm -f "$2"; }
for f in dbip-country-lite.mmdb dbip-asn-lite.mmdb; do copy "$DATA_DIR/geoip/$f" "$W/nfa/geoip/$f"; done
for f in ieee-oui.csv ieee-mam.csv ieee-oui36.csv; do copy "$DATA_DIR/oui/$f" "$W/nfa/oui/$f"; done
[[ -s $W/nfa/geoip/dbip-country-lite.mmdb ]] || echo "warning: no GeoIP data from $DATA_DIR; countries and organizations will be missing"

# Collector ports offset by 10000 so they never meet real exporters.
python3 - "$W/nfa/config.db" <<'PY'
import json, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
s = {"rawRetentionDays": 7, "rollupRetentionDays": 365, "netflowPort": 12055, "ipfixPort": 14739, "sflowPort": 16343,
     "applianceName": "Tributary", "sessionHours": 12, "reverseDns": False, "onlineAsnLookup": False,
     "localNetworks": ["2001:db8:10::/48", "203.0.113.0/24"], "dnsServers": [], "exporterAllowlist": []}
c.execute("INSERT OR REPLACE INTO settings VALUES ('settings', ?)", (json.dumps(s),))
c.commit()
PY

# Tributary first: it creates the database schema the backfill writes to.
echo "==> starting Tributary"
NFA_ADMIN_PASSWORD=Screenshots-2026 "$W/nfad" -data "$W/nfa" -listen 127.0.0.1:8443 -redirect-http 127.0.0.1:8080 \
  -ch-addr 127.0.0.1:19000 -ch-http-addr 127.0.0.1:18123 -ch-user default -ch-password-file /dev/null > "$W/nfad.log" 2>&1 &
pids+=($!)
until curl -sfk https://127.0.0.1:8443/healthz >/dev/null; do sleep 1; done

echo "==> backfilling $HISTORY of traffic"
geo=()
[[ -s $W/nfa/geoip/dbip-country-lite.mmdb ]] && geo=(-geoip-dir "$W/nfa/geoip")
"$W/flowgen" -backfill "$HISTORY" -backfill-rate 30 -ch-addr 127.0.0.1:19000 -ch-user default -ch-password-file /dev/null "${geo[@]}" > "$W/backfill.log" 2>&1
result=$(tail -1 "$W/backfill.log") # its summary: "backfilled N records (N written, N dropped)"
echo "$result"
if ! [[ $result =~ \(([0-9]+)\ written ]] || (( BASH_REMATCH[1] == 0 )); then
  tail -5 "$W/backfill.log" >&2
  die "the backfill wrote nothing"
fi

# Simulated remote hosts aren't on real threat feeds: list a few in a local
# "Demo watchlist" feed (added by shots.mjs) and tag the backfilled flows,
# which bypass ingest, as Tributary would have.
clickhouse client --port 19000 -q "
  SELECT IPv6NumToString(dst_addr) AS a FROM netflow.flows
  WHERE startsWith(a, '::ffff:') AND NOT match(a, '^::ffff:(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|203\\.0\\.113\\.)')
  GROUP BY dst_addr ORDER BY cityHash64(dst_addr) LIMIT 6" | sed 's/^::ffff://' > "$W/watchlist.txt"
[[ -s $W/watchlist.txt ]] || die "no remote addresses for the demo watchlist"
in=$(sed "s/.*/toIPv6('&')/" "$W/watchlist.txt" | paste -sd,)
clickhouse client --port 19000 --mutations_sync 1 -q "ALTER TABLE netflow.flows UPDATE src_threat = 'Demo watchlist' WHERE src_addr IN ($in)"
clickhouse client --port 19000 --mutations_sync 1 -q "ALTER TABLE netflow.flows UPDATE dst_threat = 'Demo watchlist' WHERE dst_addr IN ($in)"

"$W/flowgen" -target 127.0.0.1 -port-offset 10000 -rate 200 > "$W/flowgen.log" 2>&1 &
pids+=($!)
sleep 20 # live counters and templates

echo "==> taking screenshots into $OUT"
mkdir -p "$OUT"
BASE=https://127.0.0.1:8443 PASSWORD=Screenshots-2026 WATCHLIST=$W/watchlist.txt OUT=$OUT CHROME=$CHROME node "$HERE/shots.mjs"

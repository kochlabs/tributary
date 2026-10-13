#!/bin/bash
# Privileged helper for Tributary's administration pages (Updates, Time,
# Services). Runs as root, started by systemd only:
#   tributary-admin.sh          consume the web UI's request (tributary-admin.path)
#   tributary-admin.sh check    refresh package lists (daily timer)
#
# The web service (user nfa) writes a small JSON request. Every field is
# validated against an allowlist here; nothing is passed to a shell unchecked.
set -uo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive

REQ=/var/lib/nfa/admin-request/request.json
STATE=/var/lib/tributary-admin
SERVICES_CONF=/etc/tributary/services.conf
TIMESYNC_CONF=/etc/systemd/timesyncd.conf.d/tributary.conf
LOG=$STATE/log
STATUS=$STATE/status.json

install -d -o root -g nfa -m 750 "$STATE"

publish() { # file <- stdin, readable by the web service
  cat > "$1.tmp" && chgrp nfa "$1.tmp" && chmod 640 "$1.tmp" && mv -f "$1.tmp" "$1"
}

req='{}'
if [[ $# -gt 0 ]]; then
  req=$(jq -n --arg a "$1" '{action:$a}')
else
  # Never follow a symlink planted by the unprivileged side.
  if [[ -L $REQ || ! -f $REQ ]]; then rm -f "$REQ"; exit 0; fi
  req=$(head -c 65536 "$REQ")
  rm -f "$REQ"
  jq -e 'type == "object"' >/dev/null 2>&1 <<<"$req" || { echo "malformed request" >&2; exit 1; }
fi
field() { jq -r "$1 // empty" <<<"$req"; }
action=$(field .action)
id=$(field .id | tr -dc 'a-z0-9' | head -c 32)

result() { # ok message
  jq -n --arg id "$id" --arg action "$action" --argjson ok "$1" --arg msg "$2" --argjson at "$(date -u +%s)" \
    '{id:$id, action:$action, ok:$ok, message:$msg, at:$at}' | publish "$STATE/result.json"
}
fail() { result false "$1"; echo "$1" >&2; exit 1; }

# ---------------------------------------------------------------- updates
now() { date -u +%s; }
prev() { [[ -f $STATUS ]] && jq -r "$1 // empty" "$STATUS" 2>/dev/null; }

upgradable_json() {
  apt list --upgradable 2>/dev/null | awk -F'[/ \\[\\]]' 'NR>1 && NF {
      name=$1; suite=$2; ver=$3; from=$(NF-1)
      sec = (suite ~ /security/) ? "true" : "false"
      printf "{\"name\":\"%s\",\"suite\":\"%s\",\"version\":\"%s\",\"from\":\"%s\",\"security\":%s}\n", name, suite, ver, from, sec
    }' | jq -s '.'
}

write_status() { # state exitCode
  local pkgs; pkgs=$(upgradable_json 2>/dev/null || echo '[]')
  jq -n --arg state "$1" --arg action "$action" --argjson started "$started" \
    --argjson finished "$( [[ $1 == running ]] && echo null || now )" \
    --argjson exit "${2:-null}" --argjson lastCheck "${last_check:-null}" \
    --argjson lastInstall "${last_install:-null}" --argjson lastInstallExit "${last_install_exit:-null}" \
    --argjson pkgs "${pkgs:-[]}" --argjson reboot "$( [[ -f /run/reboot-required ]] && echo true || echo false )" \
    --arg os "$(. /etc/os-release && echo "$PRETTY_NAME")" --arg kernel "$(uname -r)" \
    '{state:$state, action:$action, startedAt:$started, finishedAt:$finished, exitCode:$exit,
      lastCheck:$lastCheck, lastInstall:$lastInstall, lastInstallExit:$lastInstallExit, upgradable:$pkgs,
      rebootRequired:$reboot, os:$os, kernel:$kernel}' | publish "$STATUS"
}

log() { echo "[$(date -u +%H:%M:%S)] $*" >> "$LOG"; }
run() { log "\$ $*"; "$@" >> "$LOG" 2>&1; }

do_updates() {
  exec 9>"$STATE/lock"
  flock -n 9 || fail "another update action is running"
  started=$(now)
  last_check=$(prev .lastCheck)
  last_install=$(prev .lastInstall)
  last_install_exit=$(prev .lastInstallExit)
  : > "$LOG"; chgrp nfa "$LOG"; chmod 640 "$LOG"
  write_status running
  local rc=0
  case $action in
    check)
      run apt-get update || rc=$?
      [[ $rc -eq 0 ]] && last_check=$(now)
      ;;
    upgrade)
      run apt-get update || rc=$?
      if [[ $rc -eq 0 ]]; then
        last_check=$(now)
        # Keep existing config files; never remove packages.
        run apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --with-new-pkgs upgrade || rc=$?
        run apt-get -y autoclean || true
      fi
      last_install=$(now); last_install_exit=$rc
      ;;
    reboot)
      log "Restart requested; rebooting in 5 seconds."
      write_status done 0
      result true "restarting"
      systemd-run --on-active=5 --unit=tributary-reboot systemctl reboot >/dev/null
      exit 0
      ;;
  esac
  if [[ $rc -eq 0 ]]; then log "Finished successfully."; write_status done 0; result true "ok"
  else log "Failed with exit code $rc."; write_status failed "$rc"; result false "exit code $rc"; fi
  exit "$rc"
}

# ---------------------------------------------------------------- time
valid_server() { # hostname, IPv4 or IPv6
  [[ ${#1} -le 253 ]] && { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ $1 =~ ^[0-9A-Fa-f:.]+$ && $1 == *:* ]]; }
}

do_time() {
  local tz ntp servers=()
  tz=$(field .timezone)
  ntp=$(jq -r 'if .ntp == true then "true" elif .ntp == false then "false" else "" end' <<<"$req")
  [[ -n $tz ]] && { timedatectl list-timezones | grep -Fxq -- "$tz" || fail "unknown time zone: $tz"; }
  [[ -n $ntp ]] || fail "ntp must be true or false"
  mapfile -t servers < <(jq -r '(.servers // [])[]' <<<"$req")
  [[ ${#servers[@]} -le 10 ]] || fail "at most 10 NTP servers"
  for s in "${servers[@]}"; do valid_server "$s" || fail "invalid NTP server: $s"; done

  if [[ ${#servers[@]} -gt 0 ]]; then
    install -d -m 755 "$(dirname "$TIMESYNC_CONF")"
    printf '# Managed by Tributary (Administration > Time)\n[Time]\nNTP=%s\n' "${servers[*]}" > "$TIMESYNC_CONF"
  else
    rm -f "$TIMESYNC_CONF" # fall back to the distribution defaults
  fi
  [[ -n $tz ]] && { timedatectl set-timezone -- "$tz" || fail "could not set time zone"; }
  timedatectl set-ntp "$ntp" || fail "could not change NTP synchronisation"
  if [[ $ntp == true ]]; then systemctl restart systemd-timesyncd || fail "could not restart systemd-timesyncd"; fi
  result true "time settings applied"
}

# ---------------------------------------------------------------- services
do_service() {
  local unit op allowed
  unit=$(field .unit); op=$(field .op)
  [[ $unit =~ ^[A-Za-z0-9@._-]{1,128}$ && $op =~ ^[a-z]{1,16}$ ]] || fail "malformed unit or operation"
  allowed=$(awk -v u="$unit" '$1 == u { $1 = ""; print }' "$SERVICES_CONF")
  [[ -n $unit && " $allowed " == *" $op "* && -n $op ]] || fail "operation '$op' is not permitted on '$unit'"
  systemctl "$op" -- "$unit" 2>"$STATE/service.err" || fail "systemctl $op $unit failed: $(head -c 300 "$STATE/service.err")"
  result true "$unit: $op done"
}

case $action in
  check|upgrade|reboot) do_updates ;;
  time) do_time ;;
  service) do_service ;;
  *) fail "unknown action: $action" ;;
esac

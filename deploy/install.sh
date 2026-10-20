#!/usr/bin/env bash
# Installs or upgrades Tributary on Debian/Ubuntu from its .deb package.
#
# The package depends on clickhouse-server, which Debian doesn't ship, so this
# first sets up ClickHouse's own apt repository: it checks the repository's
# signing key against a pinned fingerprint, and restricts the repository to
# ClickHouse's packages so it can never replace anything else on the system.
# docs/INSTALL.md describes the same steps for doing them by hand.
#
#   sudo deploy/install.sh [-y] [tributary_X_amd64.deb]
#
#   -y   don't ask before changing apt sources (for unattended installs)
#   With no package, installs the newest dist/tributary_*_amd64.deb.
set -euo pipefail

CH_KEY_URL=https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key
# ClickHouse Inc. Repositories Key <packages@clickhouse.com>
CH_KEY_FPR=3A9EA1193A97B548BE1457D48919F6BD2B48D754
CH_KEYRING=/usr/share/keyrings/clickhouse-keyring.gpg
CH_SOURCES=/etc/apt/sources.list.d/clickhouse.list
CH_PREFS=/etc/apt/preferences.d/clickhouse
CH_REPO="deb [signed-by=$CH_KEYRING] https://packages.clickhouse.com/deb lts main"
CH_PIN=$(cat <<'EOF'
# Written by Tributary's installer: only ClickHouse's own packages may come
# from its repository, so it can never replace other system packages.
Package: clickhouse-*
Pin: origin packages.clickhouse.com
Pin-Priority: 500

Package: *
Pin: origin packages.clickhouse.com
Pin-Priority: -1
EOF
)

die() { echo "install.sh: $*" >&2; exit 1; }

usage() { sed -n '2,14s/^# \{0,1\}//p' "$0"; exit "${1:-0}"; }

YES=no
DEB=
for a in "$@"; do
  case $a in
    -y|--yes) YES=yes ;;
    -h|--help) usage ;;
    -*) usage 1 ;;
    *) [[ -z $DEB ]] || usage 1; DEB=$a ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
command -v apt-get >/dev/null && command -v dpkg >/dev/null || die "needs a Debian or Ubuntu system (apt and dpkg)"
[[ $(dpkg --print-architecture) == amd64 ]] || die "the package is built for amd64; this system is $(dpkg --print-architecture)"

# Resolve the package from where the script was run, then fall back to the
# repository's dist/ directory.
if [[ -n $DEB ]]; then
  [[ -f $DEB ]] || die "no such file: $DEB"
  DEB=$(realpath "$DEB")
else
  DEB=$(ls -t "$(dirname "$(realpath "$0")")"/../dist/tributary_*_amd64.deb 2>/dev/null | head -1 || true)
  [[ -n $DEB ]] || die "no package found: run 'make deb' or pass the .deb path"
  DEB=$(realpath "$DEB")
fi

confirm() {
  [[ $YES == yes ]] && return 0
  [[ -t 0 ]] || die "not running interactively: rerun with -y to accept these changes"
  local answer
  read -r -p "$1 [y/N] " answer
  [[ $answer == [yY]* ]]
}

# Prints the fingerprints of the primary keys in a key file, one per line.
fingerprints() {
  gpg --batch --quiet --no-default-keyring --with-colons --show-keys "$1" 2>/dev/null |
    awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }'
}

# Fails unless the key file holds exactly the pinned ClickHouse key.
check_key() {
  local fprs
  fprs=$(fingerprints "$1")
  if [[ $fprs != "$CH_KEY_FPR" ]]; then
    echo "expected ClickHouse key: $CH_KEY_FPR" >&2
    echo "found:                   ${fprs:-(none)}" >&2
    return 1
  fi
}

need_tools() {
  local missing=()
  command -v curl >/dev/null || missing+=(curl)
  command -v gpg >/dev/null || missing+=(gnupg)
  [[ -e /etc/ssl/certs/ca-certificates.crt ]] || missing+=(ca-certificates)
  if (( ${#missing[@]} )); then
    echo "==> installing ${missing[*]}"
    apt-get update -qq
    apt-get install -y -qq "${missing[@]}"
  fi
}

changed=no
if [[ ! -s $CH_KEYRING || ! -f $CH_SOURCES ]]; then
  cat <<EOF
Tributary needs ClickHouse, which comes from ClickHouse's own apt repository.
This adds:
  $CH_KEYRING   their signing key (fingerprint checked)
  $CH_SOURCES   $CH_REPO
  $CH_PREFS   only clickhouse-* packages may come from it
EOF
  confirm "Add the ClickHouse repository?" || die "cancelled; see docs/INSTALL.md to set it up yourself"
  need_tools
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  echo "==> fetching the ClickHouse signing key"
  curl -fsSL --proto '=https' --tlsv1.2 "$CH_KEY_URL" -o "$tmp/key.asc"
  gpg --batch --quiet --dearmor --yes -o "$tmp/key.gpg" "$tmp/key.asc"
  check_key "$tmp/key.gpg" || die "the downloaded key is not ClickHouse's known key; not adding the repository"
  install -m 644 "$tmp/key.gpg" "$CH_KEYRING"
  printf '%s\n' "$CH_REPO" > "$CH_SOURCES"
  chmod 644 "$CH_SOURCES"
  changed=yes
else
  # Set up earlier (by hand or an older installer): check what's trusted.
  need_tools
  check_key "$CH_KEYRING" || die "$CH_KEYRING doesn't hold exactly ClickHouse's known key; check it before continuing"
fi

if [[ ! -f $CH_PREFS || $(cat "$CH_PREFS") != "$CH_PIN" ]]; then
  if [[ $changed == no ]]; then
    echo "The ClickHouse repository is configured but not restricted to ClickHouse's packages."
    confirm "Add $CH_PREFS to restrict it?" || die "cancelled"
  fi
  printf '%s\n' "$CH_PIN" > "$CH_PREFS"
  chmod 644 "$CH_PREFS"
  echo "==> restricted the ClickHouse repository to clickhouse-* packages"
  changed=yes
fi

if [[ $changed == yes ]] || ! apt-cache show clickhouse-server >/dev/null 2>&1; then
  apt-get update -qq
fi

echo "==> installing $(basename "$DEB")"
# ClickHouse would otherwise prompt for a default-user password; it only
# listens on localhost and Tributary uses its own credentials.
DEBIAN_FRONTEND=noninteractive CLICKHOUSE_PASSWORD='' apt-get install -y "$DEB"
echo "Point flow exporters at UDP 2055 (NetFlow), 4739 (IPFIX) or 6343 (sFlow)."

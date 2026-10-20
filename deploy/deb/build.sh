#!/bin/bash
# Builds dist/tributary_<version>_amd64.deb from bin/ and deploy/.
# Usage: deploy/deb/build.sh <version>
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=$1
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
chmod 755 "$ROOT" # becomes the mode of "./" in the archive

install -D -m 755 bin/nfad                              "$ROOT/usr/bin/nfad"
install -D -m 755 bin/flowgen                           "$ROOT/usr/bin/tributary-flowgen"
install -D -m 755 deploy/admin/tributary-admin.sh       "$ROOT/usr/lib/tributary/tributary-admin.sh"
install -D -m 644 deploy/admin/services.conf            "$ROOT/etc/tributary/services.conf"
install -D -m 644 deploy/clickhouse/tributary.xml       "$ROOT/etc/clickhouse-server/config.d/tributary.xml"
install -D -m 644 deploy/99-tributary.conf              "$ROOT/usr/lib/sysctl.d/99-tributary.conf"
for u in deploy/nfad.service deploy/admin/tributary-admin.path deploy/admin/tributary-admin.service \
         deploy/admin/tributary-update-check.service deploy/admin/tributary-update-check.timer; do
  install -D -m 644 "$u" "$ROOT/usr/lib/systemd/system/$(basename "$u")"
done
install -D -m 644 README.md                             "$ROOT/usr/share/doc/tributary/README.md"
install -D -m 644 docs/INSTALL.md                       "$ROOT/usr/share/doc/tributary/INSTALL.md"
install -D -m 644 deploy/deb/copyright                  "$ROOT/usr/share/doc/tributary/copyright"
install -D -m 644 LICENSE                                "$ROOT/usr/share/doc/tributary/LICENSE"
install -D -m 644 NOTICE                                 "$ROOT/usr/share/doc/tributary/NOTICE"
install -D -m 644 THIRD_PARTY_NOTICES.md                 "$ROOT/usr/share/doc/tributary/THIRD_PARTY_NOTICES.md"
install -D -m 644 deploy/deb/lintian-overrides          "$ROOT/usr/share/lintian/overrides/tributary"
# Native-package changelog generated from git history.
{
  echo "tributary ($VERSION) unstable; urgency=medium"
  echo
  git log --no-merges --format='  * %s' -n 50 2>/dev/null || echo "  * Build $VERSION"
  echo
  echo " -- dkoch <drkoch@gmail.com>  $(date -R)"
} | gzip -9n > "$ROOT/usr/share/doc/tributary/changelog.gz"
chmod 644 "$ROOT/usr/share/doc/tributary/changelog.gz"

mkdir -p "$ROOT/DEBIAN"
SIZE=$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$SIZE/" deploy/deb/control.in > "$ROOT/DEBIAN/control"
install -m 644 deploy/deb/conffiles "$ROOT/DEBIAN/conffiles"
install -m 755 deploy/deb/postinst deploy/deb/prerm deploy/deb/postrm "$ROOT/DEBIAN/"

mkdir -p dist
OUT=dist/tributary_${VERSION}_amd64.deb
dpkg-deb --root-owner-group --build -Zxz "$ROOT" "$OUT" >/dev/null
echo "$OUT"

#!/bin/sh
# Prints the ClickHouse user definitions Tributary installs in
# /etc/clickhouse-server/users.d/ (used by the package's postinst).
#
#   users.sh netflow <sha256 of password>   the user Tributary connects as
#   users.sh default <sha256 of password>   a password for ClickHouse's built-in
#                                           administrator, which otherwise has none
set -eu

[ $# -eq 2 ] && printf %s "$2" | grep -Eq '^[0-9a-f]{64}$' || { echo "usage: $0 netflow|default <sha256 hex>" >&2; exit 2; }

case $1 in
netflow)
  # Only from this machine, no user management, and table rights on its own
  # database plus the system tables it reads for storage figures and schema
  # checks: no other databases, files, URLs, named collections or server
  # administration. (Not GRANT ALL, which also covers access entities and
  # named collections that happen to share the database's name.)
  cat <<XML
<clickhouse>
  <profiles><default><max_memory_usage>1000000000</max_memory_usage></default></profiles>
  <users>
    <netflow>
      <password_sha256_hex>$2</password_sha256_hex>
      <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
      <profile>default</profile><quota>default</quota>
      <access_management>0</access_management>
      <grants>
        <query>GRANT SHOW, SELECT, INSERT, ALTER, CREATE, DROP, TRUNCATE, OPTIMIZE ON netflow.*</query>
        <query>GRANT SELECT ON system.parts</query>
        <query>GRANT SELECT ON system.columns</query>
        <query>GRANT SELECT ON system.disks</query>
      </grants>
    </netflow>
  </users>
</clickhouse>
XML
  ;;
default)
  cat <<XML
<clickhouse>
  <users>
    <default>
      <password remove="1"/>
      <password_sha256_hex>$2</password_sha256_hex>
    </default>
  </users>
</clickhouse>
XML
  ;;
*)
  echo "usage: $0 netflow|default <sha256 hex>" >&2
  exit 2
  ;;
esac

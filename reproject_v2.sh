#!/bin/sh
# Re-derive the index rows of one v2 source from its archive files (schema or projection change). Claims and SHA
# tables are unaffected. Usage: reproject_v2.sh <source name>
set -eu
name=$1; cd /opt/webcat-monitor
clickhouse-client -q "DELETE FROM webcat.entries WHERE log = '$name'"
first=$(awk 'BEGIN{RS=";\n"} /INSERT INTO webcat.entries/ {print; exit}' load_v2.sql)
n=0; for f in /srv/archive/rekor-v2/$name/parsed/*.parquet; do
  until clickhouse-client --param_log="$name" --param_file="${f#/srv/archive/}" -q "$first"; do sleep 15; done; n=$((n+1))
done; echo "re-projected $n files for $name"

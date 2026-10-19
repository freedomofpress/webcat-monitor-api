#!/bin/sh
# Re-derive the index rows of one v2 source from its archive files (schema or projection change): entries,
# entries_by_index, entries_by_time. The dedup tables (claims, sha, artifact) are left alone. Usage: reproject_v2.sh <source>
set -eu
name=$1; cd /opt/webcat-monitor
for t in entries entries_by_index entries_by_time; do clickhouse-client -q "DELETE FROM webcat.$t WHERE log = '$name'"; done
n=0; for f in /srv/archive/rekor-v2/$name/parsed/*.parquet; do
  # statements 1-5 of load_v2.sql: truncate stage, project, fan out to the three row tables
  awk 'BEGIN{RS=";\n"; ORS=";\n"} /TRUNCATE TABLE webcat.stage_v2|INSERT INTO webcat.stage_v2|SELECT \* FROM webcat.stage_v2|FROM webcat.stage_v2/' load_v2.sql > /tmp/reproject.sql
  until clickhouse-client --param_log="$name" --param_file="${f#/srv/archive/}" --multiquery < /tmp/reproject.sql; do sleep 15; done; n=$((n+1))
done; echo "re-projected $n files for $name"

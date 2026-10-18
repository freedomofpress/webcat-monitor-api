#!/bin/sh
# Rekor v1 history: pull the BigQuery export from the bucket, verify it, load it into ClickHouse. Resumable.
# Runs as the clickhouse user. Usage: v1_ingest.sh [download|load|all]
set -eu
BUCKET=${BUCKET:-gs://webcat-511408-rekor-export}
DST=/srv/archive/rekor-v1/export
DONE=$DST/loaded.txt
cd /opt/webcat-monitor
step=${1:-all}

if [ "$step" = download ] || [ "$step" = all ]; then
  mkdir -p "$DST"
  gcloud storage rsync -r "$BUCKET/" "$DST/" 2>&1 | tail -2
  gcloud storage ls -l -r "$BUCKET/**" | grep parquet | awk '{print $1, $3}' | sed "s|$BUCKET/||" | sort > /tmp/remote.txt
  (cd "$DST" && find . -name '*.parquet' -printf '%s %P\n' | sed 's|^\([0-9]*\) \./|\1 |' | sort) > /tmp/local.txt
  diff /tmp/remote.txt /tmp/local.txt && echo "download verified: $(wc -l < /tmp/local.txt) objects"
fi

if [ "$step" = load ] || [ "$step" = all ]; then
  touch "$DONE"
  n=0
  for f in "$DST"/v1/part-*.parquet; do
    rel=${f#/srv/archive/}
    grep -qx "$rel" "$DONE" && continue
    clickhouse-client --param_file="$rel" --multiquery < load_v1.sql
    echo "$rel" >> "$DONE"; n=$((n + 1))
    [ $((n % 200)) -eq 0 ] && echo "$(date -u +%FT%TZ) loaded $n files this run, $(wc -l < "$DONE") total"
  done
  echo "load complete: $(wc -l < "$DONE") files"
fi

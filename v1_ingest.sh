#!/bin/sh
# Rekor v1 history: pull the BigQuery export from the bucket, verify it, load it into ClickHouse. Resumable.
# Runs as the clickhouse user. Usage: v1_ingest.sh [download|load|all]
set -eu
BUCKET=${BUCKET:-gs://webcat-511408-rekor-export}
DST=/srv/archive/rekor-v1/export
DONE=$DST/loaded.txt
cd /opt/webcat-monitor
step=${1:-all}

if { [ "$step" = download ] || [ "$step" = all ]; } && [ ! -f "$DST/download.verified" ]; then
  # Runs once. After verification the files are made read-only and this block never runs again,
  # so a deleted bucket or a re-run can never touch the local copy (re-exporting costs ~75 USD).
  mkdir -p "$DST"
  gcloud storage rsync -r "$BUCKET/" "$DST/" 2>&1 | tail -2
  gcloud storage ls -l -r "$BUCKET/**" | grep parquet | awk '{print $1, $3}' | sed "s|$BUCKET/||" | sort > /tmp/remote.txt
  (cd "$DST" && find . -name '*.parquet' -printf '%s %P\n' | sed 's|^\([0-9]*\) \./|\1 |' | sort) > /tmp/local.txt
  diff /tmp/remote.txt /tmp/local.txt && echo "download verified: $(wc -l < /tmp/local.txt) objects"
  chmod -R a-w "$DST/v1" "$DST/v1_artifacts"
  date -u +%FT%TZ > "$DST/download.verified"
fi

if [ "$step" = load ] || [ "$step" = all ]; then
  touch "$DONE"
  sed "s/^INSERT INTO webcat.entries/INSERT INTO webcat.staging/" load_v1.sql > /tmp/load_v1_staging.sql
  n=0
  for f in "$DST"/v1/part-*.parquet; do
    rel=${f#/srv/archive/}
    grep -qx "$rel" "$DONE" && continue
    # One file = one atomic step: load into an empty staging table, then attach its parts to the index.
    # Retry on failure: the memory cap is shared with the v2 fetcher, and a failed file leaves nothing in the index.
    try=0
    until clickhouse-client -n -q "DROP TABLE IF EXISTS webcat.staging; CREATE TABLE webcat.staging AS webcat.entries;" \
          && clickhouse-client --param_file="$rel" --multiquery < /tmp/load_v1_staging.sql; do
      try=$((try + 1)); [ $try -ge 20 ] && { echo "giving up on $rel"; exit 1; }
      echo "retry $try for $rel"; sleep 30
    done
    clickhouse-client -q "ALTER TABLE webcat.entries ATTACH PARTITION ID 'all' FROM webcat.staging"
    echo "$rel" >> "$DONE"; n=$((n + 1))
    [ $((n % 200)) -eq 0 ] && echo "$(date -u +%FT%TZ) loaded $n files this run, $(wc -l < "$DONE") total"
  done
  clickhouse-client -q "DROP TABLE IF EXISTS webcat.staging"
  echo "load complete: $(wc -l < "$DONE") files"
fi

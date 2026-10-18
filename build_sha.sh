#!/bin/sh
# One-time build of webcat.sha from the archives: v1 export Parquet (SHAs are extension values 1.3 and 1.13)
# and v2 parsed Parquet. Resumable via a done-list. Daily loads append on their own afterwards.
set -eu
DONE=/srv/index/sha_build.done; touch "$DONE"
S="SETTINGS max_threads = 1, max_memory_usage = 1500000000, input_format_parquet_use_native_reader = 1, input_format_parquet_max_block_size = 4096"
run() { until clickhouse-client -q "$1"; do echo "retry: $2"; sleep 30; done; echo "$2" >> "$DONE"; }
for f in /srv/archive/rekor-v1/export/v1/part-*.parquet; do
  rel=${f#/srv/archive/}; grep -qx "$rel" "$DONE" && continue
  run "INSERT INTO webcat.sha SELECT DISTINCT unhex(h) AS sha, 'rekor-v1' AS log, toUInt64(LogIndex) AS log_index
       FROM file('$rel', Parquet)
       ARRAY JOIN arrayMap(x -> ifNull(x.2, ''), arrayFilter(x -> x.1 IN ('1.3.6.1.4.1.57264.1.3', '1.3.6.1.4.1.57264.1.13'), Extensions)) AS h
       WHERE LogIndex IS NOT NULL AND length(h) = 40 AND match(h, '^[0-9a-f]{40}$') $S" "$rel"
done
for f in /srv/archive/rekor-v2/*/parsed/*.parquet; do
  rel=${f#/srv/archive/}; log=$(echo "$rel" | cut -d/ -f2); grep -qx "$rel" "$DONE" && continue
  run "INSERT INTO webcat.sha SELECT DISTINCT unhex(h) AS sha, '$log' AS log, log_index FROM file('$rel', Parquet)
       ARRAY JOIN [ext['1.3.6.1.4.1.57264.1.3'], ext['1.3.6.1.4.1.57264.1.13']] AS h
       WHERE length(h) = 40 AND match(h, '^[0-9a-f]{40}$') $S" "$rel"
done
echo "sha build complete: $(wc -l < "$DONE") files"

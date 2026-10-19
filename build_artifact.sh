#!/bin/sh
# One-time build of webcat.artifact from the v2 archives (after the archive rewrite, every chunk has artifact_digest).
set -eu
DONE=/srv/index/artifact_build.done; touch "$DONE"
for f in /srv/archive/rekor-v2/*/parsed/*.parquet; do
  rel=${f#/srv/archive/}; log=$(echo "$rel" | cut -d/ -f2); grep -qx "$rel" "$DONE" && continue
  until clickhouse-client -q "INSERT INTO webcat.artifact SELECT DISTINCT unhex(artifact_digest), '$log', log_index FROM file('$rel', Parquet) WHERE length(artifact_digest) = 64 SETTINGS max_threads = 1, max_memory_usage = 1500000000"; do sleep 30; done
  echo "$rel" >> "$DONE"
done
echo "artifact build complete: $(wc -l < "$DONE") files"

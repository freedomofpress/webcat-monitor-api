#!/bin/sh
# Post-load build, run once as the clickhouse user after v1 and v2 history are in webcat.entries:
# keys skip index, claims side table, SHA table, then the benchmark. Needs config.d/storage.xml installed first.
set -eu
cd /opt/webcat-monitor
clickhouse-client --multiquery < schema.sql
echo "$(date -u +%FT%TZ) rewriting early v2 archive chunks with the full record (artifact digest, raw keys)"
python3 monitor.py --rewrite-archive 306000 log2025-1
echo "$(date -u +%FT%TZ) re-projecting v2 (index time = cert not_before)"; ./reproject_v2.sh log2025-1
echo "$(date -u +%FT%TZ) materializing the keys index"
clickhouse-client -q "ALTER TABLE webcat.entries MATERIALIZE INDEX ext_keys SETTINGS mutations_sync = 0"
until [ "$(clickhouse-client -q "SELECT count() FROM system.mutations WHERE table = 'entries' AND NOT is_done")" = 0 ]; do sleep 60; done
echo "$(date -u +%FT%TZ) building claims"; python3 build_claims.py
echo "$(date -u +%FT%TZ) building sha"; ./build_sha.sh
echo "$(date -u +%FT%TZ) final merges"; clickhouse-client -q "OPTIMIZE TABLE webcat.claims FINAL"; clickhouse-client -q "OPTIMIZE TABLE webcat.sha FINAL"
clickhouse-client --output-format PrettyCompactNoEscapes -q "SELECT table, sum(rows) AS rows, formatReadableSize(sum(bytes_on_disk)) AS size FROM system.parts WHERE active AND database = 'webcat' GROUP BY table"
echo "$(date -u +%FT%TZ) benchmark"; ./bench.sh | tee /srv/index/bench.txt

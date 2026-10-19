#!/bin/sh
# Post-load build, once, as the clickhouse user, after v1 and v2 history are in webcat.entries. Order matters:
# complete the archive first, then re-derive v2 rows, then every derived table, then the benchmark.
# Needs config.d/storage.xml installed and ClickHouse restarted (the chain does that).
set -eu
cd /opt/webcat-monitor
clickhouse-client --multiquery < schema.sql
echo "$(date -u +%FT%TZ) rewriting early v2 archive chunks with the full record (artifact digest, raw keys)"
python3 monitor.py --rewrite-archive 306000 log2025-1
echo "$(date -u +%FT%TZ) re-projecting v2 (index time = cert not_before; fills by_index/by_time for v2)"
./reproject_v2.sh log2025-1
echo "$(date -u +%FT%TZ) materializing the keys index"
clickhouse-client -q "ALTER TABLE webcat.entries MATERIALIZE INDEX ext_keys SETTINGS mutations_sync = 0"
until [ "$(clickhouse-client -q "SELECT count() FROM system.mutations WHERE table = 'entries' AND NOT is_done")" = 0 ]; do sleep 60; done
echo "$(date -u +%FT%TZ) building claims"; python3 build_ranges.py claims
echo "$(date -u +%FT%TZ) building entries_by_index and entries_by_time for v1 (v2 rows came from the re-projection)"
clickhouse-client -q "DELETE FROM webcat.entries_by_index WHERE log = 'rekor-v1'"; clickhouse-client -q "DELETE FROM webcat.entries_by_time WHERE log = 'rekor-v1'"
python3 build_ranges.py by_index; python3 build_ranges.py by_time
echo "$(date -u +%FT%TZ) building sha"; ./build_sha.sh
echo "$(date -u +%FT%TZ) building artifact"; ./build_artifact.sh
echo "$(date -u +%FT%TZ) final merges"
for t in claims sha artifact; do clickhouse-client -q "OPTIMIZE TABLE webcat.$t FINAL"; done
clickhouse-client --output-format PrettyCompactNoEscapes -q "SELECT table, sum(rows) AS rows, formatReadableSize(sum(bytes_on_disk)) AS size, groupUniqArray(disk_name) AS disks FROM system.parts WHERE active AND database = 'webcat' GROUP BY table"
echo "$(date -u +%FT%TZ) benchmark"; ./bench.sh | tee /srv/index/bench.txt

#!/bin/sh
# Runs every query in bench.sql on an idle box and prints the timings from the query log.
cd /opt/webcat-monitor
i=0; grep -E "^SELECT" bench.sql | while IFS= read -r q; do i=$((i+1)); clickhouse-client --query_id="bench_$i" -q "${q%;}" >/dev/null 2>&1 || echo "bench_$i failed"; done
clickhouse-client -q "SYSTEM FLUSH LOGS" >/dev/null
clickhouse-client --output-format PrettyCompactNoEscapes -q "
SELECT toUInt32(replaceOne(query_id, 'bench_', '')) AS n, query_duration_ms AS ms, formatReadableQuantity(read_rows) AS rows_read, formatReadableSize(read_bytes) AS bytes_read, formatReadableSize(memory_usage) AS mem
FROM system.query_log WHERE type = 'QueryFinish' AND query_id LIKE 'bench_%' AND event_time > now() - INTERVAL 1 HOUR ORDER BY n"
grep -E "^-- [0-9]+\." bench.sql

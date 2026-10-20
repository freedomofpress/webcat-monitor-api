#!/bin/sh
# Concurrency benchmark: fires the sub-second queries of bench.sql at parallelism 1, 4, 8 and 16 and reports, per
# level, the wall time of the whole batch and the p50/p95 single-query latency from the query log.
# Usage: bench_concurrent.sh [repeats per query, default 5]
cd /opt/webcat-monitor
N=${1:-5}
grep -E "^SELECT" bench.sql | grep -vE "webcat.entries WHERE issuer = |FROM webcat.entries WHERE time BETWEEN|FROM webcat.entries WHERE log = 'rekor-v1' AND log_index = " > /tmp/fast.sql
echo "$(wc -l < /tmp/fast.sql) query shapes, $N repeats each"
for P in 1 4 8 16; do
  tag="cb${P}_$(date +%s)"
  i=0; : > /tmp/jobs.txt
  while IFS= read -r q; do i=$((i+1)); r=0; while [ $r -lt "$N" ]; do r=$((r+1)); printf '%s\t%s\n' "${tag}_q${i}_r${r}" "${q%;}" >> /tmp/jobs.txt; done; done < /tmp/fast.sql
  start=$(date +%s.%N)
  sort -R /tmp/jobs.txt | xargs -P "$P" -d '\n' -I{} sh -c 'id=$(printf "%s" "{}" | cut -f1); q=$(printf "%s" "{}" | cut -f2-); clickhouse-client --query_id="$id" -q "$q" >/dev/null 2>&1'
  end=$(date +%s.%N)
  clickhouse-client -q "SYSTEM FLUSH LOGS" >/dev/null
  clickhouse-client --output-format PrettyCompactNoEscapes -q "
    SELECT $P AS parallel, count() AS queries, round($end - $start, 1) AS batch_s, round(count() / ($end - $start), 1) AS qps,
           quantile(0.5)(query_duration_ms) AS p50_ms, quantile(0.95)(query_duration_ms) AS p95_ms, max(query_duration_ms) AS max_ms
    FROM system.query_log WHERE type = 'QueryFinish' AND query_id LIKE '${tag}_%'"
done

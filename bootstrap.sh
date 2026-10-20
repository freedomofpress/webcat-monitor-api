#!/bin/sh
# History from the entry points, on a box prepared by setup.sh. Run as the clickhouse user (or via sudo -u), in a
# tmux session or a transient unit: the whole thing takes a day or two and every step is resumable.
#   1. Rekor v1 export from BigQuery into the bucket (skipped if the bucket already has it or the archive does)
#   2. Rekor v1 history: pull, verify, freeze, load
#   3. Rekor v2 shard backfill: verify, archive, index (the daily monitor does the same incrementally)
#   4. Sigsum logs
#   5. Derived tables: keys index, claims, by_index/by_time, sha, artifact, leaves
#   6. Rekor v1 leaf-list verification, live sampling
# Afterwards: the daily timer keeps everything current; quality.py repair <N> clears the dataset's identity gaps.
set -eu
cd /opt/webcat-monitor
export CLOUDSDK_CONFIG=/srv/index/gcloud HOME=/srv/index
bucket=$(python3 -c "import tomllib; print(tomllib.load(open('sources.toml','rb'))['gcp']['bucket'])")

[ -f /srv/archive/rekor-v1/export/download.verified ] || gcloud storage ls "$bucket/v1/" >/dev/null 2>&1 || python3 rekor_v1.py export
python3 rekor_v1.py load-history
python3 monitor.py $(python3 -c "import tomllib; print(' '.join(s['name'] for s in tomllib.load(open('sources.toml','rb'))['source'] if s['type'] == 'rekor-v2'))")
python3 monitor.py $(python3 -c "import tomllib; print(' '.join(s['name'] for s in tomllib.load(open('sources.toml','rb'))['source'] if s['type'] == 'sigsum'))")
python3 build.py all
python3 verify.py
python3 quality.py sample
echo "bootstrap complete; see /srv/index/verification.json and bench.sh"

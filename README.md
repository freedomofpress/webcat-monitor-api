# webcat-monitor

The log auditor behind `webcat audit` and explore.webcat.tech: mirrors, verifies and indexes every transparency log
WEBCAT trusts, and serves a read-only API over the index. One box, two volumes, one unprivileged user.

## Entry points

- Sigsum logs: `get-tree-head` and `get-leaves` of each log in `sources.toml`.
- Rekor v2 shards: the tlog-tiles endpoints (`checkpoint`, `tile/0/N`, `tile/entries/N`).
- Rekor v1: Google's BigQuery dataset `bigquery-public-data.rekor` (the v1 API serves one entry per request; the
  log holds 3.3 billion), plus the live API for sampling and repairs.
- Keys for every signature are pinned in `sources.toml`: Sigsum log and witness keys, the Rekor v2 shard key and the
  Rekor v1 key from the Sigstore trusted root. A rotation shows up as a verification failure, never a silent switch.

## Layout

| | |
|---|---|
| `/srv/archive` (HDD) | the archives: `rekor-v1/export` (the BigQuery export, frozen) and `rekor-v1/daily/<run>` increments, `rekor-v2/<shard>/parsed` chunks and `tile/0` hash tiles; plus the HDD tier of ClickHouse |
| `/srv/index` (NVMe) | ClickHouse, the Sigsum SQLite index, state and verification files |
| `/opt/webcat-monitor` | this checkout |

Archive files are written once and made read-only. The only in-place rewrite is `quality.py repair`, which replaces
placeholder rows of a v1 export file with rows the live log yields, in the file's own schema.

## Lifecycle

```
setup.sh [--gcp-key FILE]      fresh Debian 13 -> packages, ClickHouse, configs, schema, services (idempotent, root)
bootstrap.sh                   history from the entry points: v1 export+load, v2 backfill, Sigsum, derived tables, verification
snapshot.sh make|restore PATH  the two volumes, rsync'd with ClickHouse stopped; restore onto a set-up box instead of bootstrapping
```

The daily run is `webcat-monitor.timer` (03:24 UTC): `monitor.py` fetches every source, verifies, loads, refreshes
the per-log totals. Manual runs take source names: `monitor.py seasalp log2025-1`.

## Code

| File | Does |
|---|---|
| `sources.toml` | the only configuration: paths, GCP project, API bind, every log with its pinned key, witness keys |
| `schema.sql` | every table; applied by setup, safe to re-apply |
| `monitor.py` | daily entry point; `type` in the config picks the fetcher |
| `sigsum.py` | leaves into SQLite by signer key; root rehashed; tree head signature and cosignatures |
| `rekor_v2.py` | bundles verified against hash tiles, certificates extracted to the archive, loaded by `load_v2.sql`; checkpoint signature; tile roots vs checkpoint |
| `rekor_v1.py` | daily APPENDS increment; `export` and `load-history` for the one-time history |
| `verify.py` | Merkle frontier and consistency proofs; signed notes, checkpoints, Sigsum and Rekor v1 tree heads; the v1 leaf-list check |
| `quality.py` | `sample`: live entries vs the index; `repair`: identities the dataset lacks, from the live log, in place |
| `build.py` | derived tables for bootstrap (resumable, memory-bounded); `reproject` after a projection change |
| `load_v1.sql`, `load_v2.sql` | one archive file -> stage table -> entries, by_index, by_time, claims, sha, artifact (and leaves for v1) |
| `api.py` | read-only JSON; see STATUS.md for endpoints |
| `bench.sql`, `bench.sh` | latency per query shape from the query log |
| `test.py` | offline checks: tile paths, bundle framing, Merkle and proofs, DER text, note parsing |

## Tables

`entries` (by identity: every claim shape), `entries_by_index` (lookups and ranges by log index; dedups on merge),
`entries_by_time` (date ranges, newest first), `claims` (distinct OID, value, identity: exact and prefix claim search),
`sha` (git SHA to entry), `artifact` (artifact digest to entry, v2), `leaves_v1` (leaf hashes for the tree check),
`stats` (per-log totals for the API). Storage: `tiered` = NVMe then HDD; `sha`, `artifact`, `leaves_v1` HDD only.

## Verification

Every daily run: Sigsum leaves to root, tree head signature, witness cosignatures; Rekor v2 entries to tiles, tiles
to checkpoint, checkpoint signature; Rekor v1 tree head signatures, the leaf list per shard against the signed heads
(consistency proof for the active shard), 200 live entries compared with the index. Results in
`/srv/index/verification.json`, served under `verification` in `/v1/status`. Not verifiable: the content of Rekor v1
rows, since the dataset has no leaf bodies; hence the sampling and the repair.

## Security

Everything runs as the unprivileged `clickhouse` user with systemd sandboxing; ClickHouse listens on localhost only;
the API queries through a read-only ClickHouse user capped at 2 threads, 500 MB and 10 s, with 8 queries in flight
and a bounded queue; archives are read-only files; the Google service account has job-user, dataset-editor and
bucket rights on the one project, activated into `/srv/index/gcloud` (0700). Put the API behind TLS (Caddy) before
giving it a hostname.

## Volumes (fstab)

```
LABEL=index   /srv/index   ext4 defaults,noatime,discard 0 2
LABEL=archive /srv/archive ext4 defaults,noatime 0 2
```

Format the HDD with `mkfs.ext4 -E nodiscard`: a whole-device discard on virtual block storage can hang for a long time.

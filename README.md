# webcat-monitor

Mirrors, verifies and indexes the transparency logs WEBCAT trusts, and serves a read-only API over the index.
Used by `webcat audit` and explore.webcat.tech. See STATUS.md for sizes, latencies and the API examples.

## Architecture

```
 Sigsum logs ──get-tree-head/get-leaves──▶ sigsum.py ──▶ /srv/index/sigsum.db (leaves by signer key)
 Rekor v2 shards ──tlog-tiles──▶ rekor_v2.py ──▶ /srv/archive/rekor-v2/<shard>/{parsed/*.parquet, tile/0/*}
 Rekor v1 ──BigQuery dataset──▶ rekor_v1.py ──▶ /srv/archive/rekor-v1/{export,daily}/*.parquet
                                                        │ load_v1.sql / load_v2.sql
                                                        ▼
            ClickHouse (/srv/index): entries · entries_by_index · entries_by_time · claims · sha · artifact · leaves_v1
                                                        │
 verify.py (Merkle roots, proofs, signatures) ──▶ /srv/index/verification.json ──▶ api.py ──▶ clients
 quality.py (live sampling, in-place repair of the v1 dataset's gaps)
```

- Archives are the source of truth: written once, read-only, in the data's own schema. The index is a projection
  (`build.py reproject` rebuilds it; the loaders append to it daily).
- Every signature is verified against a key pinned in `sources.toml`; every leaf set is rehashed to a signed root.
- One unprivileged user (`clickhouse`) owns both volumes and runs everything; ClickHouse listens on localhost; the API
  reads through a read-only user capped per query.

## Instructions

A Debian 13 box with two volumes mounted at `/srv/index` (NVMe) and `/srv/archive` (HDD):

```
LABEL=index   /srv/index   ext4 defaults,noatime,discard 0 2     # mkfs.ext4 -L index
LABEL=archive /srv/archive ext4 defaults,noatime 0 2             # mkfs.ext4 -L archive -E nodiscard
```

Then, as root, from a checkout:

```
./setup.sh --gcp-key service-account.json   # packages, ClickHouse, configs, schema, services; idempotent
sudo -u clickhouse ./bootstrap.sh            # history from the endpoints: ~1 day, ~25 USD of BigQuery + egress
   or:  ./snapshot.sh restore <source>       # the two volumes from a snapshot instead
```

The Google service account needs `bigquery.jobUser`, `bigquery.dataEditor` and `objectAdmin` on the bucket in
`sources.toml`. Nothing else is required: the Sigsum and Rekor endpoints are public.

Daily: `webcat-monitor.timer` runs `monitor.py` at 03:24 UTC under one lock. Manual: `monitor.py <source> ...`.
Check: `curl localhost:8080/v1/status`, `journalctl -u webcat-monitor`. Benchmarks: `./bench.sh`.
Snapshot: `./snapshot.sh make user@host:/backups/webcat/` (stops ClickHouse for the copy).
Tests: `python3 test.py` (stdlib only).

## Files

| | |
|---|---|
| `sources.toml` | configuration: paths, GCP, API bind, logs with pinned keys, witness keys |
| `schema.sql` | tables; `clickhouse.xml`, `clickhouse-users.xml` server and API user |
| `setup.sh`, `bootstrap.sh`, `snapshot.sh` | lifecycle |
| `monitor.py` | daily entry point; `sigsum.py`, `rekor_v2.py`, `rekor_v1.py` fetchers |
| `verify.py` | Merkle frontier and consistency proofs; signed notes, checkpoints, Sigsum and Rekor v1 tree heads; v1 leaf list |
| `quality.py` | `sample`: live entries vs the index; `repair`: fills what the v1 dataset lacks, in place |
| `build.py` | derived tables (bootstrap), `reproject` after a projection change |
| `load_v1.sql`, `load_v2.sql` | one archive file -> every table |
| `api.py` + units | the API; `bench.sql`, `bench.sh`; `test.py` |

## Verification

Each daily run: Sigsum leaves to the signed root, tree head signature, witness cosignatures; Rekor v2 entries to hash
tiles, tiles to the checkpoint, checkpoint signature; Rekor v1 tree head signatures, the leaf list per shard against
the signed heads (consistency proof for the active shard, entries the dataset lacks fetched from the log), 200 random
live entries compared with the index. Not verifiable: Rekor v1 row content, since the dataset has no leaf bodies.

## Security notes

Keys are pinned, never fetched at runtime. Services run sandboxed as `clickhouse` (`ProtectSystem=strict`). The API
is plain HTTP on the configured bind; put Caddy in front for TLS. The service account key lives in
`/srv/index/gcloud` (0700) and can only touch the one project. Archives are read-only files; the only in-place writes
are `quality.py repair`, serialized by a lock, replacing dataset placeholders with rows from the live log.

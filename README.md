# webcat-monitor

The log auditor for [WEBCAT](https://github.com/freedomofpress/webcat). It mirrors the transparency logs WEBCAT
trusts (Sigsum logs, Rekor v1 and v2), verifies them, indexes every signer identity and claim, and serves the result
as a small read-only API. It gives the full signing history of an enrolled site, which neither Rekor's search nor
Sigsum offer by themselves. The [explorer](https://github.com/freedomofpress/webcat-explorer) will use it for
per-site history, and a `webcat audit` command for the [CLI](https://github.com/freedomofpress/webcat-cli) is in
draft.

The live instance is at https://monitor-api.webcat.tech. Current sizes, latencies and endpoint examples are in
[STATUS.md](STATUS.md).

## What it answers

- Every Rekor entry whose certificate satisfies an enrollment's claims, with the extension's own matching rules
  (all claims must match, `^` means prefix, the SAN claim matches any SAN).
- Every Sigsum leaf signed by a given key, in the logs an enrollment names.
- Entries by log index, by git commit, by artifact digest; status and verification results per log.

```
GET /v1/sigstore/history?claims[2.5.29.17]=^https://github.com/freedomofpress/&claims[1.3.6.1.4.1.57264.1.8]=https://token.actions.githubusercontent.com
GET /v1/sigsum/history?signer=<base64url public key>
GET /v1/entry/rekor-v1/3081692656   GET /v1/sha/<40 hex>   GET /v1/artifact/<64 hex>   GET /v1/status
```

Answers are JSON. Claim queries are key-range lookups and take milliseconds on 3.4 billion rows.

## Where the data comes from

- **Sigsum logs**: `get-tree-head` and `get-leaves`, every leaf kept.
- **Rekor v2**: the tlog-tiles endpoints. Every bundle is checked against its hash tile, every certificate is
  extracted to an archive, the bundle is dropped.
- **Rekor v1**: Google's public BigQuery dataset of the log. The v1 API serves one entry per request and the log
  holds over three billion, so the history comes from a one-time export and daily `APPENDS` increments. The dataset
  refreshes irregularly, days behind the log, and the live API (about twenty entries per second at a polite rate,
  against fifteen million new entries a day) cannot stand in for it. It has no leaf bodies and some gaps; the live
  API is used to sample it daily and to fill what it lacks.

Everything lands in two volumes: the archives on an HDD, written once and read-only, and a ClickHouse index on an
NVMe that is a projection of them. The index can be rebuilt from the archives at any time.

## What is verified, every cycle

- Sigsum: leaves rehashed to the signed tree head; tree head signature and witness cosignatures.
- Rekor v2: entries to hash tiles, tiles to the checkpoint, checkpoint signature.
- Rekor v1: tree head signatures; the full leaf list per shard against the signed heads, with a consistency proof for
  the active shard; 200 random live entries compared with the index.

Keys are pinned in `sources.toml` and never fetched at runtime. What cannot be verified is the content of Rekor v1
rows, because the dataset carries no leaf bodies; that is what the daily sampling is for.

## Running it

A Debian 13 box with an NVMe at `/srv/index` and an HDD at `/srv/archive`, and a Google service account with
`bigquery.jobUser`, `bigquery.dataEditor` and `objectAdmin` on the bucket named in `sources.toml`. Then:

```
./setup.sh --gcp-key service-account.json   # packages, ClickHouse, config, schema, services
sudo -u clickhouse ./bootstrap.sh            # the history from the endpoints: about a day, ~25 USD of BigQuery
```

or, from an existing deployment, `./snapshot.sh make <dest>` there and `./snapshot.sh restore <src>` here instead of
bootstrapping. After that systemd timers run `monitor.py`: Sigsum and Rekor v2 every half hour, Rekor v1 nightly. `python3 test.py` runs the offline checks.

## Code

| | |
|---|---|
| `sources.toml` | the configuration: volumes, GCP project, API bind, logs and their keys |
| `monitor.py` | the timers' entry point; `sigsum.py`, `rekor_v2.py`, `rekor_v1.py` fetch and load one log type each |
| `verify.py` | Merkle trees and proofs, signed notes and checkpoints, Sigsum and Rekor tree heads |
| `quality.py` | live sampling of Rekor v1, and the in-place repair of the dataset's gaps |
| `build.py`, `load_v1.sql`, `load_v2.sql`, `schema.sql` | the index |
| `api.py` | the API |
| `setup.sh`, `bootstrap.sh`, `snapshot.sh` | lifecycle |

Everything runs as one unprivileged user, ClickHouse listens on localhost, the API queries through a read-only
database user with per-query limits, and the archives are read-only files. nginx terminates TLS with a Let's Encrypt
certificate for the hostname in `sources.toml`.

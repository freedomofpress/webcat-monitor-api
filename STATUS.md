# Log auditor: status (2026-10-20)

Follow-up for freedomofpress/webcat#222.

## Setup and cost

- One VPS at Onidel: 4 vCPU, 6 GB RAM, 100 GB NVMe + 1 TB HDD, **[€/month]**.
- One-off: Rekor v1 history from the Google BigQuery dataset, ~71 USD of queries (three passes) + ~25 USD egress, paid from trial credit.
- Ongoing: daily `APPENDS` increment inside the BigQuery free tier, cents of egress, ~5 USD/month for an off-box copy of the export in a bucket.

## What is stored

| Table | Rows | Size |
|---|---|---|
| Archive on the HDD (v1 export + increments, v2 parsed chunks + hash tiles, Sigsum leaves) | 3.38 B entries | 210 GB |
| `entries` (by identity: every claim shape) | 3.38 B | 9.5 GB |
| `entries_by_index` (lookups and ranges by log index) | same | 19 GB |
| `entries_by_time` (date ranges, newest first) | same | 12.6 GB |
| `claims` (distinct OID, value, identity) | 48.8 M | 0.4 GB |
| `sha` (git commit to entries) | 388 M | 0.9 GB |
| `artifact` (artifact digest to entries, v2 only) | 161 M | 5.3 GB |

Growth: ~35 M entries/day across both Rekor logs, ~0.5 GB/day of index. NVMe tiers to the HDD when full.

## Verification, nightly, reported by the API

- Sigsum: leaves rehashed to the signed tree head; tree head signature and witness cosignatures checked against pinned keys.
- Rekor v2: entries checked against hash tiles, tiles against the checkpoint, checkpoint signature against the trusted-root key.
- Rekor v1: tree head signatures checked; the full leaf list (UUID = tree id + leaf hash) hashed per shard and compared to the signed heads, the active shard via a consistency proof; 200 random entries/day fetched from the live log and compared with the index.
- Found by the sampling: the dataset omits the identity for ~2.5 M DSSE entries from 2024 that do carry a certificate. Being repaired in place from the live log.

## Query latency (idle, warm cache, 3.4 B rows)

| Query | ms |
|---|---|
| Identity exact or prefix (org, repo), with or without issuer | 10 to 75 |
| Common Fulcio OID, exact or prefix, via `claims` | 20 to 900 |
| Rare or custom OID: present, exact, prefix | 140 to 220 |
| Log index, "since index N", time range, newest overall | 15 to 160 |
| Commit SHA, artifact digest | 100 to 600 |

Throughput saturates at ~25 mixed queries/s on 4 cores; p95 under 0.3 s at 4 in flight, under 1 s at 16. Network from Europe adds ~0.65 s per request.

## API

Read-only JSON at `http://216.176.239.201:8080` (hostname and TLS pending). Claim semantics are the extension's: all claims must match, `^` prefixes, the SAN claim matches any SAN.

```
# everything freedomofpress signed through GitHub Actions
GET /v1/sigstore/history?claims[2.5.29.17]=^https://github.com/freedomofpress/&claims[1.3.6.1.4.1.57264.1.8]=https://token.actions.githubusercontent.com

# an enrollment's actual claims (lsd.cat)
GET /v1/sigstore/history?claims[1.3.6.1.4.1.57264.1.8]=https://token.actions.githubusercontent.com&claims[1.3.6.1.4.1.57264.1.9]=https://github.com/lsd-cat/lsdv2/.github/workflows/hugo.yml@refs/heads/main&claims[1.3.6.1.4.1.57264.1.12]=https://github.com/lsd-cat/lsdv2&claims[1.3.6.1.4.1.57264.1.14]=refs/heads/main

# same as a POST body
POST /v1/sigstore/history
{"claims": {"1.3.6.1.4.1.57264.1.8": "https://token.actions.githubusercontent.com", "1.3.6.1.4.1.57264.1.12": "https://github.com/lsd-cat/lsdv2"}, "limit": 500}

# a Sigsum signer's leaves in the enrolled logs
GET /v1/sigsum/history?signer=wzRAXpRuYr5CHZmCAdK1Jh2widMU8GOwCNhONOHkV8k

GET /v1/entry/rekor-v1/3081692656
GET /v1/sha/06e0a2a35efa7c4b6c8771e080a805ed3bf72dd6
GET /v1/artifact/4f0a230f351e315bef22714ff5f85798c9103fba7c66f87e76942d8fcb33e8ee
GET /v1/status
```

Consumers (both in draft, not merged): a `webcat audit <domain>` command for webcat-cli; per-site Sigstore history in webcat-explorer.

## Limits

- Rekor v1 trails the live log by the dataset's refresh lag (8 days today); v2 is current to the hour.
- v1 content cannot be hash-verified (no leaf bodies in the dataset), hence the daily sampling.
- v2 witness cosignatures not yet verified (no pinned witness keys).

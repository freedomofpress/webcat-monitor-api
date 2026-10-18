# webcat-monitor

Mirrors and verifies the transparency logs WEBCAT trusts, on one box with an NVMe index volume and an HDD archive volume.

- `sources.toml` lists every log instance. `type` selects the fetcher; `sigsum`, `rekor-v2`, `rekor-v1`.
- `monitor.py [NAME ...]` brings each source up to date. Runs daily from the systemd timer.
- Sigsum: all leaves in `/srv/index/sigsum.db`, table `leaves(log, idx, key_hash, checksum, signature)`, indexed by `key_hash`. Root recomputed and checked against the tree head each run.
- Rekor v2: each entry bundle is verified against its level-0 hash tile, every signer certificate is parsed (`python3-cryptography`) into a `webcat.entries` row in ClickHouse, the hash tiles are kept under `/srv/archive/rekor-v2/<name>/tile/0/` for the tree check, and the bundle is dropped (`keep_bundles = true` keeps it zstd-compressed). Tile roots are verified against the checkpoint each run.
- ClickHouse: `schema.sql` defines `webcat.entries`, one row per entry and signer: log, log index, time, kind, issuer, identity, and a map of Fulcio and custom OIDs. Measured 6.3 bytes/row. `load_v1.sql` loads one v1 Parquet file.
- Rekor v1: history comes from the BigQuery export (`rekor_v1_export.sh`), loaded with `load_v1.sql`. Daily increments via APPENDS are not wired yet.

Deploy: `rsync -a --exclude .git ./ root@HOST:/opt/webcat-monitor/ && ssh root@HOST 'cp /opt/webcat-monitor/webcat-monitor.* /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now webcat-monitor.timer'`

Not verified yet: Sigsum tree head signatures and witness cosignatures, Rekor checkpoint signatures. Both need ed25519, which the stdlib lacks. The signed material is stored raw so it can be checked later.

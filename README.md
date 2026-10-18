# webcat-monitor

Mirrors and verifies the transparency logs WEBCAT trusts, on one box with an NVMe index volume and an HDD archive volume.

- `sources.toml` lists every log instance. `type` selects the fetcher; `sigsum`, `rekor-v2`, `rekor-v1`.
- `monitor.py [NAME ...]` brings each source up to date. Runs daily from the systemd timer.
- Sigsum: all leaves in `/srv/index/sigsum.db`, table `leaves(log, idx, key_hash, checksum, signature)`, indexed by `key_hash`. Root recomputed and checked against the tree head each run.
- Rekor v2: tlog-tiles mirror under `/srv/archive/rekor-v2/<name>/` with gzipped entry bundles and raw level-0 hash tiles. Each bundle is verified against its hash tile; tile roots are verified against the checkpoint.
- Rekor v1: placeholder. History comes from the BigQuery export, not wired yet.

Deploy: `rsync -a --exclude .git ./ root@HOST:/opt/webcat-monitor/ && ssh root@HOST 'cp /opt/webcat-monitor/webcat-monitor.* /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now webcat-monitor.timer'`

Not verified yet: Sigsum tree head signatures and witness cosignatures, Rekor checkpoint signatures. Both need ed25519, which the stdlib lacks. The signed material is stored raw so it can be checked later.

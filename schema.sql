-- One row per (log entry, signer identity). Searchable fields only; the archive on the HDD holds the rest.
-- Sort key: identity first, so "everything for this org or repo" is a prefix range scan.
-- Measured 2026-10-18 on 1.3M v1 rows: 6.3 bytes/row on disk.
CREATE DATABASE IF NOT EXISTS webcat;
CREATE TABLE IF NOT EXISTS webcat.entries (
  log LowCardinality(String),                         -- source name from sources.toml
  log_index UInt64 CODEC(Delta, ZSTD),
  time DateTime CODEC(Delta, ZSTD),                   -- v1: integrated time; v2: time of our fetch (the leaf carries none)
  kind LowCardinality(String),                        -- hashedrekord, dsse, intoto, ...
  issuer LowCardinality(String),                      -- Fulcio OIDC issuer; else cert issuer DN; else key type
  identity String CODEC(ZSTD(3)),                     -- SAN URI, else SAN email, else PGP user id, else sha256 of the key
  ext Map(LowCardinality(String), String) CODEC(ZSTD(3))  -- Fulcio + custom OIDs, minus per-entry noise (SHAs, run ids)
) ENGINE = MergeTree ORDER BY (identity, log, log_index);

-- Skip index: which OIDs occur in each block. Makes any query on a rare (custom) OID touch only its blocks.
ALTER TABLE webcat.entries ADD INDEX IF NOT EXISTS ext_keys mapKeys(ext) TYPE set(100) GRANULARITY 4;

-- Claims side table: distinct (oid, value, identity). Values are nearly constant per identity, so this stays small
-- (estimate 1-3 GB) while turning "which identities carry claim X" (exact or prefix) into a key range scan.
-- The main table then resolves those identities on its own key. Built by build_claims.py, appended daily by the loaders.
CREATE TABLE IF NOT EXISTS webcat.claims (
  oid LowCardinality(String),
  value String CODEC(ZSTD(3)),
  identity String CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree ORDER BY (oid, value, identity);

-- Commit lookup: one row per (git SHA, entry). ~30 bytes/row, ~100 GB for the history, so it lives on the HDD
-- (storage policy "hdd", see config.d/storage.xml). Exact SHA lookup is one seek on the sort key.
CREATE TABLE IF NOT EXISTS webcat.sha (
  sha FixedString(20),
  log LowCardinality(String),
  log_index UInt64
) ENGINE = ReplacingMergeTree ORDER BY (sha, log, log_index) SETTINGS storage_policy = 'hdd';

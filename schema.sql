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

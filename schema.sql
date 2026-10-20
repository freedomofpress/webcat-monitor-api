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
-- Query with has(mapKeys(ext), '<oid>'); mapContains() is not recognised by the index.
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

-- Tiering: NVMe while it fits, overflow to the HDD part by part (policy "tiered"). The SHA table stays HDD-only.
ALTER TABLE webcat.entries MODIFY SETTING storage_policy = 'tiered';
ALTER TABLE webcat.claims MODIFY SETTING storage_policy = 'tiered';

-- Same rows as entries, ordered by (log, log_index): point lookups, "since index N" ranges, resolving SHA or
-- artifact hits to rows, latest-entries feeds. ~25-30 GB for the history. Filled by the loaders and build_copies.py.
-- ReplacingMergeTree with identity in the key: a retried multi-part insert cannot leave duplicates behind.
CREATE TABLE IF NOT EXISTS webcat.entries_by_index AS webcat.entries
  ENGINE = ReplacingMergeTree ORDER BY (log, log_index, identity) SETTINGS storage_policy = 'tiered';

-- Narrow time-ordered copy: "what was signed between these dates", newest overall. ~10 GB for the history.
CREATE TABLE IF NOT EXISTS webcat.entries_by_time (
  time DateTime CODEC(Delta, ZSTD),
  log LowCardinality(String),
  log_index UInt64 CODEC(Delta, ZSTD),
  kind LowCardinality(String),
  issuer LowCardinality(String),
  identity String CODEC(ZSTD(3))
) ENGINE = MergeTree ORDER BY (time, log, log_index) SETTINGS storage_policy = 'tiered';

-- Artifact digests of v2 entries (the v1 dataset has none): search by the hash an entry attests. HDD, ~40 B/row.
CREATE TABLE IF NOT EXISTS webcat.artifact (
  digest FixedString(32),
  log LowCardinality(String),
  log_index UInt64
) ENGINE = ReplacingMergeTree ORDER BY (digest, log, log_index) SETTINGS storage_policy = 'hdd';

-- Staging for one v2 chunk: projected once, fanned out to entries, entries_by_index and entries_by_time.
CREATE TABLE IF NOT EXISTS webcat.stage_v2 AS webcat.entries ENGINE = Memory;

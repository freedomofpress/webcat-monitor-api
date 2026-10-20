-- Applied by setup.sh; safe to re-apply. Storage policies: "tiered" = NVMe, spilling to the HDD; "hdd" = HDD only.
CREATE DATABASE IF NOT EXISTS webcat;

-- One row per (entry, signer identity), sorted by identity: every claim shape is a key range. ~5 bytes/row.
CREATE TABLE IF NOT EXISTS webcat.entries (
  log LowCardinality(String),
  log_index UInt64 CODEC(Delta, ZSTD),
  time DateTime CODEC(Delta, ZSTD),
  kind LowCardinality(String),
  issuer LowCardinality(String),
  identity String CODEC(ZSTD(3)),
  ext Map(LowCardinality(String), String) CODEC(ZSTD(3))
) ENGINE = MergeTree ORDER BY (identity, log, log_index) SETTINGS storage_policy = 'tiered';
-- which OIDs occur in each block, so a rare OID touches only its blocks; query with has(mapKeys(ext), '<oid>')
ALTER TABLE webcat.entries ADD INDEX IF NOT EXISTS ext_keys mapKeys(ext) TYPE set(100) GRANULARITY 4;

-- same rows by (log, log index): lookups, "since N", resolving hash hits; dedups on merge
CREATE TABLE IF NOT EXISTS webcat.entries_by_index AS webcat.entries
  ENGINE = ReplacingMergeTree ORDER BY (log, log_index, identity) SETTINGS storage_policy = 'tiered';

-- narrow copy by time: date ranges, newest first
CREATE TABLE IF NOT EXISTS webcat.entries_by_time (
  time DateTime CODEC(Delta, ZSTD),
  log LowCardinality(String),
  log_index UInt64 CODEC(Delta, ZSTD),
  kind LowCardinality(String),
  issuer LowCardinality(String),
  identity String CODEC(ZSTD(3))
) ENGINE = MergeTree ORDER BY (time, log, log_index) SETTINGS storage_policy = 'tiered';

-- distinct (OID, value, identity): claim search, exact or prefix, resolves to identities in a key range
CREATE TABLE IF NOT EXISTS webcat.claims (
  oid LowCardinality(String),
  value String CODEC(ZSTD(3)),
  identity String CODEC(ZSTD(3))
) ENGINE = ReplacingMergeTree ORDER BY (oid, value, identity) SETTINGS storage_policy = 'tiered';

-- git commit SHA -> entry
CREATE TABLE IF NOT EXISTS webcat.sha (
  sha FixedString(20),
  log LowCardinality(String),
  log_index UInt64
) ENGINE = ReplacingMergeTree ORDER BY (sha, log, log_index) SETTINGS storage_policy = 'hdd';

-- artifact digest -> entry (Rekor v2 only; the v1 dataset has none)
CREATE TABLE IF NOT EXISTS webcat.artifact (
  digest FixedString(32),
  log LowCardinality(String),
  log_index UInt64
) ENGINE = ReplacingMergeTree ORDER BY (digest, log, log_index) SETTINGS storage_policy = 'hdd';

-- Rekor v1 leaf hashes (UUID = tree id || leaf hash) for the Merkle check against the signed tree heads
CREATE TABLE IF NOT EXISTS webcat.leaves_v1 (
  log_index UInt64 CODEC(Delta, ZSTD),
  tree_id String,
  leaf_hash FixedString(32)
) ENGINE = ReplacingMergeTree ORDER BY log_index SETTINGS storage_policy = 'hdd';

-- per-log totals for /v1/status, refreshed at the end of each full monitor run
CREATE TABLE IF NOT EXISTS webcat.stats (
  log LowCardinality(String), entries UInt64, newest DateTime, updated DateTime
) ENGINE = ReplacingMergeTree(updated) ORDER BY log;

-- staging: one archive file projected once, then fanned out
CREATE TABLE IF NOT EXISTS webcat.stage_v1 AS webcat.entries ENGINE = Memory;
CREATE TABLE IF NOT EXISTS webcat.stage_v2 AS webcat.entries ENGINE = Memory;

-- One Rekor v1 export file -> stage_v1 -> entries, entries_by_index, entries_by_time, claims, sha, leaves_v1.
-- Parameters: {file:String} path under the archive volume; {lo}, {hi} its log index range, inside which indices already
-- in leaves_v1 are skipped (the live tail and the dataset's increments overlap) unless {reload} = 1. Same identity/issuer/ext
-- rules as load_v2.sql; the raw SAN (kept by the export where the dataset's SAN columns are empty) yields the identity when
-- it is a URI or email.
SET max_threads = 1, input_format_parquet_use_native_reader = 1, input_format_parquet_max_block_size = 4096, max_insert_block_size = 65536, min_insert_block_size_rows = 65536;

-- (length, header bytes) of the DER TLV whose length byte is at offset i; lengths clamped to the input so that
-- branches evaluated on rows of another shape stay harmless
CREATE OR REPLACE FUNCTION derLen AS (v, i) ->
  if(reinterpretAsUInt8(substring(v, i, 1)) < 128,
     tuple(least(toUInt64(reinterpretAsUInt8(substring(v, i, 1))), length(v)), 1),
     tuple(least(reinterpretAsUInt64(reverse(substring(v, i + 1, least(reinterpretAsUInt8(substring(v, i, 1)) - 128, 8)))), length(v)), 1 + reinterpretAsUInt8(substring(v, i, 1)) - 128));
CREATE OR REPLACE FUNCTION derText AS (v) -> if(substring(v, 1, 1) = '\x0C', substring(v, 2 + derLen(v, 2).2), v);

TRUNCATE TABLE webcat.stage_v1;

INSERT INTO webcat.stage_v1
SELECT
  'rekor-v1' AS log,
  toUInt64(LogIndex) AS log_index,
  toDateTime(IntegratedTime) AS time,
  ifNull(Kind, '') AS kind,
  multiIf(mapContains(m, '1.3.6.1.4.1.57264.1.8'), m['1.3.6.1.4.1.57264.1.8'],
          mapContains(m, '1.3.6.1.4.1.57264.1.1'), m['1.3.6.1.4.1.57264.1.1'],
          ifNull(Issuer, '') != '', Issuer, ifNull(IdentityGoType, '')) AS issuer,
  arrayJoin(multiIf(
    length(arrayConcat(SANExtensionURIs, SANExtensionEmailAddresses)) > 0, arrayConcat(SANExtensionURIs, SANExtensionEmailAddresses),
    rawsan != '' AND substring(rawsan, 2 + derLen(rawsan, 2).2, 1) IN ('\x86', '\x81'),
      [substring(rawsan, 3 + derLen(rawsan, 2).2 + derLen(rawsan, 3 + derLen(rawsan, 2).2).2, derLen(rawsan, 3 + derLen(rawsan, 2).2).1)],
    length(PGPIdentities) > 0, PGPIdentities,
    length(Digests) > 0, [Digests[1]],
    [''])) AS identity,
  mapFilter((k, v) -> k NOT IN ('1.3.6.1.4.1.57264.1.1','1.3.6.1.4.1.57264.1.8','1.3.6.1.4.1.57264.1.3','1.3.6.1.4.1.57264.1.10',
                                '1.3.6.1.4.1.57264.1.13','1.3.6.1.4.1.57264.1.19','1.3.6.1.4.1.57264.1.15','1.3.6.1.4.1.57264.1.17',
                                '1.3.6.1.4.1.57264.1.21','2.5.29.17','1.3.6.1.5.5.7.1.1') AND NOT startsWith(k, '2.5.29.'), m) AS ext
FROM (
  SELECT *,
    ifNull(arrayFirst(x -> x.1 = '2.5.29.17', Extensions).2, '') AS rawsan,
    mapFromArrays(arrayMap(x -> ifNull(x.1, ''), Extensions), arrayMap(x -> derText(ifNull(x.2, '')), Extensions)) AS m
  FROM file({file:String}, Parquet)
)
WHERE LogIndex IS NOT NULL
  AND ({reload:UInt8} = 1 OR LogIndex NOT IN (SELECT log_index FROM webcat.leaves_v1 WHERE log_index BETWEEN {lo:UInt64} AND {hi:UInt64}));

INSERT INTO webcat.entries SELECT * FROM webcat.stage_v1;

INSERT INTO webcat.entries_by_index SELECT * FROM webcat.stage_v1;

INSERT INTO webcat.entries_by_time SELECT time, log, log_index, kind, issuer, identity FROM webcat.stage_v1;

INSERT INTO webcat.claims SELECT DISTINCT k, v, identity FROM webcat.stage_v1 ARRAY JOIN mapKeys(ext) AS k, mapValues(ext) AS v;

INSERT INTO webcat.sha
SELECT DISTINCT unhex(h), 'rekor-v1', toUInt64(LogIndex) FROM file({file:String}, Parquet)
ARRAY JOIN arrayMap(x -> ifNull(x.2, ''), arrayFilter(x -> x.1 IN ('1.3.6.1.4.1.57264.1.3', '1.3.6.1.4.1.57264.1.13'), Extensions)) AS h
WHERE LogIndex IS NOT NULL AND length(h) = 40 AND match(h, '^[0-9a-f]{40}$');

INSERT INTO webcat.leaves_v1
SELECT DISTINCT toUInt64(LogIndex), left(hex(EntryUUID), 16), substring(EntryUUID, 9, 32)
FROM file({file:String}, Parquet) WHERE LogIndex IS NOT NULL AND length(EntryUUID) = 40;

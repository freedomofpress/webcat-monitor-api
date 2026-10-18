-- Load one Rekor v1 Parquet file (rekor_v1_export.sh output) into webcat.entries.
-- Usage: clickhouse-client --param_file=rekor-v1/export/v1/part-000000000000.parquet --multiquery < load_v1.sql
-- v1_ingest.sh points the INSERT at a staging table and attaches its parts afterwards, so a failed file leaves no rows behind.
-- identity: one row per SAN URI and email (the extension accepts a claim matching any SAN); when the loader left the
-- SAN columns empty (most Fulcio certs before ~index 50M) the first GeneralName of the raw SAN if it is a URI or
-- email; else one row per PGP user id; else the key digest.
-- issuer: Fulcio OIDC issuer (1.8, else 1.1), else the certificate issuer DN, else the Go key type.
-- ext: every OID except the two issuer OIDs (moved to issuer), git SHAs 1.3/1.10/1.13/1.19, run ids 1.15/1.17,
-- run invocation URI 1.21 and the raw SAN. Those are per-entry noise for an index.
SET max_threads = 1, input_format_parquet_use_native_reader = 1, input_format_parquet_max_block_size = 4096, max_insert_block_size = 65536, min_insert_block_size_rows = 65536;  -- 5.8 GB box

CREATE OR REPLACE FUNCTION derLen AS (v, i) ->  -- (length, header bytes) of the DER TLV whose length byte is at 1-based offset i.
  -- Lengths are clamped to the input size: every branch of a multiIf is evaluated on every row, so offsets computed
  -- for the wrong shape must stay harmless (an unclamped garbage length made substring reserve gigabytes).
  if(reinterpretAsUInt8(substring(v, i, 1)) < 128,
     tuple(least(toUInt64(reinterpretAsUInt8(substring(v, i, 1))), length(v)), 1),
     tuple(least(reinterpretAsUInt64(reverse(substring(v, i + 1, least(reinterpretAsUInt8(substring(v, i, 1)) - 128, 8)))), length(v)), 1 + reinterpretAsUInt8(substring(v, i, 1)) - 128));
CREATE OR REPLACE FUNCTION derText AS (v) ->  -- Fulcio OIDs >= 1.8 are DER UTF8String (0x0C len text); older ones are raw
  if(substring(v, 1, 1) = '\x0C', substring(v, 2 + derLen(v, 2).2), v);

INSERT INTO webcat.entries
SELECT
  'rekor-v1' AS log,
  toUInt64(LogIndex) AS log_index,
  toDateTime(IntegratedTime) AS time,
  ifNull(Kind, '') AS kind,
  multiIf(
    mapContains(m, '1.3.6.1.4.1.57264.1.8'), m['1.3.6.1.4.1.57264.1.8'],
    mapContains(m, '1.3.6.1.4.1.57264.1.1'), m['1.3.6.1.4.1.57264.1.1'],
    ifNull(Issuer, '') != '', Issuer,
    ifNull(IdentityGoType, '')) AS issuer,
  arrayJoin(multiIf(
    length(arrayConcat(SANExtensionURIs, SANExtensionEmailAddresses)) > 0, arrayConcat(SANExtensionURIs, SANExtensionEmailAddresses),
    -- raw SAN fallback: the first GeneralName when it is a URI [6] or email [1]. Measured on the early log: 6 otherName-first
    -- SANs in 510k; the otherName chain cost 1.5 GB per file in SQL, so v1 skips it (v2 handles otherName in Python).
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
WHERE LogIndex IS NOT NULL;

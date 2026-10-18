-- Load one Rekor v1 Parquet file (rekor_v1_export.sh output) into webcat.entries.
-- Usage: clickhouse-client --param_file=rekor-v1/export/v1/part-000000000000.parquet --multiquery < load_v1.sql
-- identity: first SAN URI, else first SAN email, else the first GeneralName of the raw SAN when the loader
-- left the SAN columns empty (most Fulcio certs before ~index 50M), else PGP user id, else key digest.
-- issuer: Fulcio OIDC issuer (1.8, else 1.1), else the certificate issuer DN, else the Go key type.
-- ext: every OID except the two issuer OIDs (moved to issuer), git SHAs 1.3/1.10/1.13/1.19, run ids 1.15/1.17,
-- run invocation URI 1.21 and the raw SAN. Those are per-entry noise for an index.
CREATE FUNCTION IF NOT EXISTS derLen AS (v, i) ->  -- (length, header bytes) of the DER TLV whose length byte is at 1-based offset i
  if(reinterpretAsUInt8(substring(v, i, 1)) < 128,
     tuple(reinterpretAsUInt8(substring(v, i, 1)), 1),
     tuple(reinterpretAsUInt64(reverse(substring(v, i + 1, reinterpretAsUInt8(substring(v, i, 1)) - 128))), 1 + reinterpretAsUInt8(substring(v, i, 1)) - 128));
CREATE FUNCTION IF NOT EXISTS derText AS (v) ->  -- Fulcio OIDs >= 1.8 are DER UTF8String (0x0C len text); older ones are raw
  if(substring(v, 1, 1) = '\x0C', substring(v, 2 + derLen(v, 2).2), v);
CREATE FUNCTION IF NOT EXISTS sanFirst AS (v) ->  -- first GeneralName of a raw SAN if it is a URI [6] or email [1], else ''
  if(substring(v, 1, 1) = '\x30' AND substring(v, 2 + derLen(v, 2).2, 1) IN ('\x86', '\x81'),
     substring(v, 3 + derLen(v, 2).2 + derLen(v, 3 + derLen(v, 2).2).2, derLen(v, 3 + derLen(v, 2).2).1),
     '');

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
  multiIf(
    length(SANExtensionURIs) > 0, SANExtensionURIs[1],
    length(SANExtensionEmailAddresses) > 0, SANExtensionEmailAddresses[1],
    mapContains(raw, '2.5.29.17'), sanFirst(raw['2.5.29.17']),
    length(PGPIdentities) > 0, PGPIdentities[1],
    length(Digests) > 0, Digests[1],
    '') AS identity,
  mapFilter((k, v) -> k NOT IN ('1.3.6.1.4.1.57264.1.1','1.3.6.1.4.1.57264.1.8','1.3.6.1.4.1.57264.1.3','1.3.6.1.4.1.57264.1.10',
                                '1.3.6.1.4.1.57264.1.13','1.3.6.1.4.1.57264.1.19','1.3.6.1.4.1.57264.1.15','1.3.6.1.4.1.57264.1.17',
                                '1.3.6.1.4.1.57264.1.21','2.5.29.17'), m) AS ext
FROM (
  SELECT *,
    mapFromArrays(arrayMap(x -> ifNull(x.1, ''), Extensions), arrayMap(x -> ifNull(x.2, ''), Extensions)) AS raw,
    mapFromArrays(arrayMap(x -> ifNull(x.1, ''), Extensions), arrayMap(x -> derText(ifNull(x.2, '')), Extensions)) AS m
  FROM file({file:String}, Parquet)
)
WHERE LogIndex IS NOT NULL;

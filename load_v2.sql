-- Project one Rekor v2 archive file (rekor_v2.py output, one Parquet per chunk of bundles) into webcat.entries.
-- Same rules as load_v1.sql: one row per SAN value (URI, email, otherName), since the extension accepts a claim
-- matching any of them; key digest when there is no certificate;
-- issuer = Fulcio OIDC issuer (1.8, else 1.1), else certificate issuer DN, else key type;
-- ext = every OID minus the issuer OIDs and the per-entry noise (git SHAs, run ids, run invocation URI).
TRUNCATE TABLE webcat.stage_v2;

INSERT INTO webcat.stage_v2
SELECT
  {log:String} AS log,
  log_index,
  if(not_before > toDateTime('2000-01-01'), not_before, time) AS time,  -- cert issuance is within minutes of signing; the leaf has no timestamp
  kind,
  multiIf(
    mapContains(ext, '1.3.6.1.4.1.57264.1.8'), ext['1.3.6.1.4.1.57264.1.8'],
    mapContains(ext, '1.3.6.1.4.1.57264.1.1'), ext['1.3.6.1.4.1.57264.1.1'],
    issuer_dn != '', issuer_dn,
    key_details) AS issuer,
  arrayJoin(if(length(arrayConcat(san_uris, san_emails, san_other)) > 0, arrayConcat(san_uris, san_emails, san_other), [key_digest])) AS identity,
  mapFilter((k, v) -> k NOT IN ('1.3.6.1.4.1.57264.1.1','1.3.6.1.4.1.57264.1.8','1.3.6.1.4.1.57264.1.3','1.3.6.1.4.1.57264.1.10',
                                '1.3.6.1.4.1.57264.1.13','1.3.6.1.4.1.57264.1.19','1.3.6.1.4.1.57264.1.15','1.3.6.1.4.1.57264.1.17',
                                '1.3.6.1.4.1.57264.1.21','1.3.6.1.5.5.7.1.1') AND NOT startsWith(k, '2.5.29.'), ext) AS ext_index  -- not "AS ext": a SELECT alias shadows the input column of the same name
FROM file({file:String}, Parquet);

INSERT INTO webcat.entries SELECT * FROM webcat.stage_v2;

INSERT INTO webcat.entries_by_index SELECT * FROM webcat.stage_v2;

INSERT INTO webcat.entries_by_time SELECT time, log, log_index, kind, issuer, identity FROM webcat.stage_v2;

-- Claim triples for the side table (identity rule as above, every OID in the index map).
INSERT INTO webcat.claims
SELECT DISTINCT k AS oid, v AS value, identity
FROM (SELECT arrayJoin(if(length(arrayConcat(san_uris, san_emails, san_other)) > 0, arrayConcat(san_uris, san_emails, san_other), [key_digest])) AS identity,
             mapFilter((k, v) -> k NOT IN ('1.3.6.1.4.1.57264.1.1','1.3.6.1.4.1.57264.1.8','1.3.6.1.4.1.57264.1.3','1.3.6.1.4.1.57264.1.10',
                                           '1.3.6.1.4.1.57264.1.13','1.3.6.1.4.1.57264.1.19','1.3.6.1.4.1.57264.1.15','1.3.6.1.4.1.57264.1.17',
                                           '1.3.6.1.4.1.57264.1.21','1.3.6.1.5.5.7.1.1') AND NOT startsWith(k, '2.5.29.'), ext) AS m
      FROM file({file:String}, Parquet))
ARRAY JOIN mapKeys(m) AS k, mapValues(m) AS v;

-- Commit SHAs: workflow SHA (1.3) and source repository digest (1.13), one row per distinct (sha, entry).
INSERT INTO webcat.sha
SELECT DISTINCT unhex(h) AS sha, {log:String} AS log, log_index
FROM file({file:String}, Parquet)
ARRAY JOIN [ext['1.3.6.1.4.1.57264.1.3'], ext['1.3.6.1.4.1.57264.1.13']] AS h
WHERE length(h) = 40 AND match(h, '^[0-9a-f]{40}$');

-- Artifact digests (hashedrekord data digest / dsse payload hash), one row per (digest, entry).
INSERT INTO webcat.artifact
SELECT DISTINCT unhex(artifact_digest) AS digest, {log:String} AS log, log_index
FROM file({file:String}, Parquet)
WHERE length(artifact_digest) = 64;

-- One Rekor v2 archive file -> stage_v2 -> entries, entries_by_index, entries_by_time, claims, sha, artifact.
-- Parameters: {log:String} source name, {file:String} path under the archive volume.
-- identity: one row per SAN (URI, email, otherName), else the key digest. issuer: Fulcio OID 1.8, else 1.1, else the
-- certificate issuer DN, else the key type. ext: every OID minus the issuer OIDs and per-entry noise (SHAs, run ids).
TRUNCATE TABLE webcat.stage_v2;

INSERT INTO webcat.stage_v2
SELECT
  {log:String} AS log,
  log_index,
  if(not_before > toDateTime('2000-01-01'), not_before, time) AS time,
  kind,
  multiIf(mapContains(ext, '1.3.6.1.4.1.57264.1.8'), ext['1.3.6.1.4.1.57264.1.8'],
          mapContains(ext, '1.3.6.1.4.1.57264.1.1'), ext['1.3.6.1.4.1.57264.1.1'],
          issuer_dn != '', issuer_dn, key_details) AS issuer,
  arrayJoin(if(length(arrayConcat(san_uris, san_emails, san_other)) > 0, arrayConcat(san_uris, san_emails, san_other), [key_digest])) AS identity,
  mapFilter((k, v) -> k NOT IN ('1.3.6.1.4.1.57264.1.1','1.3.6.1.4.1.57264.1.8','1.3.6.1.4.1.57264.1.3','1.3.6.1.4.1.57264.1.10',
                                '1.3.6.1.4.1.57264.1.13','1.3.6.1.4.1.57264.1.19','1.3.6.1.4.1.57264.1.15','1.3.6.1.4.1.57264.1.17',
                                '1.3.6.1.4.1.57264.1.21','1.3.6.1.5.5.7.1.1') AND NOT startsWith(k, '2.5.29.'), ext) AS ext_index
FROM file({file:String}, Parquet);

INSERT INTO webcat.entries SELECT * FROM webcat.stage_v2;

INSERT INTO webcat.entries_by_index SELECT * FROM webcat.stage_v2;

INSERT INTO webcat.entries_by_time SELECT time, log, log_index, kind, issuer, identity FROM webcat.stage_v2;

INSERT INTO webcat.claims SELECT DISTINCT k, v, identity FROM webcat.stage_v2 ARRAY JOIN mapKeys(ext) AS k, mapValues(ext) AS v;

INSERT INTO webcat.sha
SELECT DISTINCT unhex(h), {log:String}, log_index FROM file({file:String}, Parquet)
ARRAY JOIN [ext['1.3.6.1.4.1.57264.1.3'], ext['1.3.6.1.4.1.57264.1.13']] AS h
WHERE length(h) = 40 AND match(h, '^[0-9a-f]{40}$');

INSERT INTO webcat.artifact
SELECT DISTINCT unhex(artifact_digest), {log:String}, log_index FROM file({file:String}, Parquet) WHERE length(artifact_digest) = 64;

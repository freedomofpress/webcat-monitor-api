-- Project one Rekor v2 archive file (rekor_v2.py output, one Parquet per chunk of bundles) into webcat.entries.
-- Same rules as load_v1.sql: identity = first SAN URI, else first SAN email, else key digest;
-- issuer = Fulcio OIDC issuer (1.8, else 1.1), else certificate issuer DN, else key type;
-- ext = every OID minus the issuer OIDs and the per-entry noise (git SHAs, run ids, run invocation URI).
INSERT INTO webcat.entries
SELECT
  {log:String} AS log,
  log_index,
  time,
  kind,
  multiIf(
    mapContains(ext, '1.3.6.1.4.1.57264.1.8'), ext['1.3.6.1.4.1.57264.1.8'],
    mapContains(ext, '1.3.6.1.4.1.57264.1.1'), ext['1.3.6.1.4.1.57264.1.1'],
    issuer_dn != '', issuer_dn,
    key_details) AS issuer,
  multiIf(
    length(san_uris) > 0, san_uris[1],
    length(san_emails) > 0, san_emails[1],
    key_digest) AS identity,
  mapFilter((k, v) -> k NOT IN ('1.3.6.1.4.1.57264.1.1','1.3.6.1.4.1.57264.1.8','1.3.6.1.4.1.57264.1.3','1.3.6.1.4.1.57264.1.10',
                                '1.3.6.1.4.1.57264.1.13','1.3.6.1.4.1.57264.1.19','1.3.6.1.4.1.57264.1.15','1.3.6.1.4.1.57264.1.17',
                                '1.3.6.1.4.1.57264.1.21'), ext) AS ext
FROM file({file:String}, Parquet)

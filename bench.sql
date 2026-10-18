-- Benchmarks for every claim shape the extension can express, plus the explorer's listing queries.
-- Run: clickhouse-client --multiquery --time < bench.sql   (times printed to stderr per statement)
SET max_threads = 4;
-- 1. SAN exact (identity lookup)
SELECT count() FROM webcat.entries WHERE identity = 'https://github.com/sigstore/sigstore-probers/.github/workflows/reusable-prober.yml@refs/heads/main';
-- 2. SAN prefix: an org
SELECT count() FROM webcat.entries WHERE identity LIKE 'https://github.com/freedomofpress/%';
-- 3. SAN prefix: a repo, latest 50 entries with their claims
SELECT log, log_index, time, issuer, ext FROM webcat.entries WHERE identity LIKE 'https://github.com/freedomofpress/securedrop/%' ORDER BY time DESC LIMIT 50 FORMAT Null;
-- 4. SAN prefix + issuer, the common WEBCAT enrollment
SELECT count() FROM webcat.entries WHERE identity LIKE 'https://github.com/freedomofpress/%' AND issuer = 'https://token.actions.githubusercontent.com';
-- 5. email identity, any issuer (identity takeover check)
SELECT issuer, count() FROM webcat.entries WHERE identity = 'keyless@distroless.iam.gserviceaccount.com' GROUP BY issuer;
-- 6. issuer only (low-cardinality column, full scan)
SELECT count() FROM webcat.entries WHERE issuer = 'https://gitlab.com';
-- 7. common OID, exact value, via the claims table then the main key
SELECT count() FROM webcat.entries WHERE identity IN (SELECT identity FROM webcat.claims WHERE oid = '1.3.6.1.4.1.57264.1.5' AND value = 'freedomofpress/securedrop') AND ext['1.3.6.1.4.1.57264.1.5'] = 'freedomofpress/securedrop';
-- 8. common OID, prefix, via the claims table then the main key
SELECT count() FROM webcat.entries WHERE identity IN (SELECT identity FROM webcat.claims WHERE oid = '1.3.6.1.4.1.57264.1.12' AND value LIKE 'https://github.com/freedomofpress/%') AND startsWith(ext['1.3.6.1.4.1.57264.1.12'], 'https://github.com/freedomofpress/');
-- 9. rare OID present at all (keys skip index)
SELECT count() FROM webcat.entries WHERE mapContains(ext, '1.3.6.1.4.1.99999.42.42');
-- 9b. rare OID, exact value (keys skip index then map)
SELECT count() FROM webcat.entries WHERE ext['1.3.6.1.4.1.99999.42.42'] = 'x';
-- 9c. map scan without any index, the old shape, for reference
SELECT count() FROM webcat.entries WHERE ext['1.3.6.1.4.1.57264.1.5'] = 'freedomofpress/securedrop';
-- 10. time range, no identity
SELECT count() FROM webcat.entries WHERE time BETWEEN '2026-10-01' AND '2026-10-02';
-- 11. pagination within an identity
SELECT log_index FROM webcat.entries WHERE identity LIKE 'https://github.com/freedomofpress/%' AND log = 'rekor-v1' AND log_index > 3000000000 ORDER BY log_index LIMIT 100 FORMAT Null;
-- 12. point lookup by log index (not in the sort key)
SELECT identity, issuer FROM webcat.entries WHERE log = 'rekor-v1' AND log_index = 3000000000;
-- 13. commit SHA lookup
SELECT log, log_index FROM webcat.sha WHERE sha = unhex('06e0a2a35efa7c4b6c8771e080a805ed3bf72dd6');
-- 14. claims table alone: identities for a repo prefix
SELECT count() FROM webcat.claims WHERE oid = '1.3.6.1.4.1.57264.1.12' AND value LIKE 'https://github.com/freedomofpress/%';

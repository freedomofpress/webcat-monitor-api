"""Rekor v1 content quality, since the dataset has no leaf bodies to hash:
- sample(): fetch random entries from the live log, confirm the leaf hash we hold, parse the certificate the way
  the v2 extractor does, compare identity, issuer and claims with the index.
- repair(): entries the dataset left without an identity although they carry a certificate (~2.56M, mostly 2024
  DSSE) get it from the live log. The export file is rewritten in place in its own schema (temp file, rename), the
  file's rows are refreshed in the index. Entries with no certificate are marked IdentityGoType = "none" so they
  leave the queue. Rate-limited and resumable: the placeholder rows are the queue.
"""
import base64, fcntl, hashlib, json, logging, os, pathlib, random, subprocess, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from rekor_v2 import record
from util import ch, get, record_status

SAMPLE = 200
BUDGET = 60000              # entries per nightly repair run; the bootstrap backlog passes the full count
WORKERS, RATE = 2, 2.0      # Rekor answers 429/503 above a few requests per second
NO_CERT_KINDS = ("rfc3161", "tuf")
RANGES = pathlib.Path("/srv/index/v1_file_ranges.json")
LOCK = "/run/lock/webcat-repair.lock"           # one repair run at a time (nightly vs backlog)
FILE_LOCK = "/run/lock/webcat-archive.lock"     # one export-file rewrite at a time (repair vs gap fill)
DROP = {"1.3.6.1.4.1.11129.2.4.2", "2.5.29.14", "2.5.29.35", "2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.17"}  # as the export
STRUCT = ("LogIndex Nullable(Int64), IntegratedTime Nullable(DateTime64(6, 'UTC')), Kind Nullable(String), EntryUUID Nullable(String), "
          "IdentityGoType Nullable(String), ID Nullable(String), Issuer Nullable(String), NotBefore Nullable(DateTime64(6, 'UTC')), "
          "Extensions Array(Tuple(Key Nullable(String), Value Nullable(String), Critical Nullable(Bool))), SANExtensionURIs Array(String), "
          "SANExtensionEmailAddresses Array(String), Digests Array(String), PGPIdentities Array(String)")
PLACEHOLDER = ("ifNull(Issuer, '') = '' AND length(Extensions) = 0 AND length(SANExtensionURIs) = 0 AND length(SANExtensionEmailAddresses) = 0 "
               "AND length(Digests) = 0 AND length(PGPIdentities) = 0 AND ifNull(IdentityGoType, '') != 'none'")
_gate, _last = threading.Lock(), [0.0]

def fetch_entry(url, idx):
    """One live entry (uuid, entry) at most RATE requests per second overall; waits through 429/503; None if the log
    will not serve it."""
    from cryptography import x509  # noqa: F401  (import check only; parsing happens in cert_from_body)
    req = urllib.request.Request(f"{url}/api/v1/log/entries?logIndex={idx}", headers={"User-Agent": "webcat-monitor (log auditor, contact: webcat@freedom.press)"})
    for n in range(200):
        with _gate:
            wait = _last[0] + 1.0 / RATE - time.monotonic()
            if wait > 0: time.sleep(wait)
            _last[0] = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return next(iter(json.loads(r.read()).items()))
        except urllib.error.HTTPError as e:
            if e.code in (429, 503): time.sleep(min(float(e.headers.get("Retry-After", 60)), 300)); continue
            if n >= 4: logging.warning("rekor-v1: index %d: HTTP %d after %d tries, skipped", idx, e.code, n + 1); return None
            time.sleep(2 ** n)
        except Exception as e:
            if n >= 9: logging.warning("rekor-v1: index %d: %s, skipped", idx, e); return None
            time.sleep(2 ** n)
    return None

def cert_from_body(body):
    """The signer certificate of a v1 entry body (hashedrekord, rekord, dsse, intoto), or None."""
    from cryptography import x509
    spec = body["spec"]
    pem = (spec.get("signature", {}).get("publicKey", {}).get("content") or (spec.get("signatures") or [{}])[0].get("verifier")
           or spec.get("publicKey") or spec.get("content", {}).get("publicKey"))
    if not pem: return None
    raw = base64.b64decode(pem)
    return x509.load_pem_x509_certificate(raw) if b"BEGIN CERTIFICATE" in raw else None

def cert_der_b64(cert):
    from cryptography.hazmat.primitives.serialization import Encoding
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode()

# --- sample ------------------------------------------------------------------------------------------------------

def sample(src):
    url = src["url"].rstrip("/")
    top = int(ch("SELECT log_index FROM webcat.entries_by_index WHERE log = 'rekor-v1' ORDER BY log_index DESC LIMIT 1 FORMAT TSV").strip())
    problems, checked, with_cert = [], 0, 0
    for i in random.sample(range(top + 1), SAMPLE):
        got_entry = fetch_entry(url, i)
        if not got_entry: continue
        uuid, v = got_entry
        body = json.loads(base64.b64decode(v["body"])); checked += 1
        leaf = hashlib.sha256(b"\x00" + base64.b64decode(v["body"])).hexdigest()
        ours = ch(f"SELECT hex(leaf_hash) FROM webcat.leaves_v1 WHERE log_index = {i} LIMIT 1 FORMAT TSV").strip().lower()
        if ours and ours != leaf: problems.append({"index": i, "what": "leaf hash", "index_has": ours, "log_has": leaf})
        if uuid[16:] != leaf: problems.append({"index": i, "what": "uuid vs body hash", "uuid": uuid, "body_hash": leaf})
        cert = cert_from_body(body)
        if not cert: continue
        with_cert += 1
        r = record(i, "", body["kind"], {"x509Certificate": {"rawBytes": cert_der_b64(cert)}}, "")
        issuer = r["ext"].get("1.3.6.1.4.1.57264.1.8") or r["ext"].get("1.3.6.1.4.1.57264.1.1") or r["issuer_dn"]
        idents = set(r["san_uris"] + r["san_emails"] + r["san_other"])
        got = [json.loads(l) for l in ch(f"SELECT identity, issuer, ext FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index = {i} FORMAT JSONEachRow").strip().split("\n") if l]
        if not got: problems.append({"index": i, "what": "certificate in the log but no identity row in the index"}); continue
        if idents and not idents & {g["identity"] for g in got}: problems.append({"index": i, "what": "identity", "index_has": [g["identity"] for g in got], "cert_has": sorted(idents)})
        if got[0]["issuer"] != issuer: problems.append({"index": i, "what": "issuer", "index_has": got[0]["issuer"], "cert_has": issuer})
        claims = {k: v for k, v in r["ext"].items() if k.startswith("1.3.6.1.4.1.57264.1.") and k.split(".")[-1] in ("2", "4", "5", "6", "9", "11", "12", "14", "16", "18", "20", "22", "23", "24")}
        bad = {k: (v, got[0]["ext"].get(k)) for k, v in claims.items() if got[0]["ext"].get(k) != v}
        if bad: problems.append({"index": i, "what": "claims", "diff": bad})
    record_status("rekor-v1-sample", {"sampled": checked, "with_certificate": with_cert, "problems": problems[:50], "problem_count": len(problems)})
    logging.log(logging.ERROR if problems else logging.INFO, "rekor-v1 sample: %d live entries checked, %d with certificates, %d problems", checked, with_cert, len(problems))
    return problems

# --- repair ------------------------------------------------------------------------------------------------------

def export_row(uuid, v):
    """A row in the export's own schema from a live entry. Returns (row, has_certificate)."""
    from cryptography import x509
    body = json.loads(base64.b64decode(v["body"]))
    t = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(v["integratedTime"]))
    row = {"LogIndex": v["logIndex"], "IntegratedTime": t, "Kind": body["kind"], "EntryUUIDHex": uuid, "IdentityGoType": "none",
           "Issuer": "", "NotBefore": "1970-01-01 00:00:00", "ExtHex": [], "SANExtensionURIs": [], "SANExtensionEmailAddresses": []}
    cert = cert_from_body(body)
    if not cert: return row, False
    row.update({"IdentityGoType": "*x509.Certificate", "Issuer": cert.issuer.rfc4514_string(), "NotBefore": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")})
    for e in cert.extensions:
        oid = e.oid.dotted_string
        if oid == "2.5.29.17":
            row["SANExtensionURIs"] = e.value.get_values_for_type(x509.UniformResourceIdentifier)
            row["SANExtensionEmailAddresses"] = e.value.get_values_for_type(x509.RFC822Name)
        elif oid not in DROP:
            raw = e.value.value if isinstance(e.value, x509.UnrecognizedExtension) else e.value.public_bytes()
            row["ExtHex"].append([oid, raw.hex(), e.critical])
    return row, True

def file_ranges(paths):
    """{relative file: [min, max LogIndex]} for every v1 Parquet in the archive, from the footers; cached, empty files skipped."""
    cached = json.loads(RANGES.read_text()) if RANGES.exists() else {}
    files = sorted(str(p.relative_to(paths["archive"])) for d in ("export/v1", "daily") for p in (paths["archive"] / "rekor-v1" / d).rglob("part-*.parquet"))
    for f in files:
        if f in cached: continue
        r = ch(f"SELECT arrayMin(arrayMap(rg -> toInt64OrNull(arrayFirst(c -> c.name = 'LogIndex', rg.columns).statistics.min), row_groups)), "
               f"arrayMax(arrayMap(rg -> toInt64OrNull(arrayFirst(c -> c.name = 'LogIndex', rg.columns).statistics.max), row_groups)) FROM file({f!r}, ParquetMetadata) FORMAT TSV").split()
        if "\\N" in r: r = ch(f"SELECT min(LogIndex), max(LogIndex) FROM file({f!r}, Parquet) SETTINGS max_threads = 1 FORMAT TSV").split()
        cached[f] = None if "\\N" in r else [int(r[0]), int(r[1])]
    RANGES.write_text(json.dumps(cached))
    return {f: v for f, v in cached.items() if f in files and v}

def replace_index_rows(indices):
    """Drop every index row for these v1 log indices, each delete riding its table's key."""
    ids = ",".join(map(str, indices))
    rows = [json.loads(l) for l in ch(f"SELECT identity, toUnixTimestamp(time) AS t FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index IN ({ids}) FORMAT JSONEachRow").strip().split("\n") if l]
    if not rows: return
    lit = lambda s: "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
    idents = ",".join(lit(i) for i in {r["identity"] for r in rows}); times = ",".join(str(t) for t in {r["t"] for r in rows})
    ch(f"DELETE FROM webcat.entries WHERE identity IN ({idents}) AND log = 'rekor-v1' AND log_index IN ({ids})")
    ch(f"DELETE FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index IN ({ids})")
    ch(f"DELETE FROM webcat.entries_by_time WHERE time IN ({times}) AND log = 'rekor-v1' AND log_index IN ({ids})")

def repair_file(url, paths, rel, idxs, missing=()):
    """Replace the placeholder rows of one export file, and add rows for `missing` indices the dataset never had.
    Returns (entries fetched, entries given an identity). Serialized per file across callers."""
    with open(FILE_LOCK, "w") as fl:
        fcntl.flock(fl, fcntl.LOCK_EX)
        return _repair_file(url, paths, rel, idxs, missing)

def _repair_file(url, paths, rel, idxs, missing):
    present = [int(x) for x in ch(f"SELECT LogIndex FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE LogIndex IN ({','.join(map(str, idxs))}) AND {PLACEHOLDER} FORMAT TSV").split()] if idxs else []
    absent = [i for i in missing if not ch(f"SELECT 1 FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE LogIndex = {i} LIMIT 1 FORMAT TSV").strip()]
    present = present + absent
    if not present: return 0, 0
    with ThreadPoolExecutor(WORKERS) as ex: fetched = [f for f in ex.map(lambda i: fetch_entry(url, i), present) if f]
    present = [v["logIndex"] for _, v in fetched]
    if not present: return 0, 0
    rows = [export_row(uuid, v) for uuid, v in fetched]
    ch("CREATE TABLE IF NOT EXISTS webcat.stage_repair (LogIndex Int64, IntegratedTime DateTime64(6, 'UTC'), Kind String, EntryUUIDHex String, "
       "IdentityGoType String, Issuer String, NotBefore DateTime64(6, 'UTC'), ExtHex Array(Tuple(String, String, Bool)), "
       "SANExtensionURIs Array(String), SANExtensionEmailAddresses Array(String)) ENGINE = Memory")
    ch("TRUNCATE TABLE webcat.stage_repair")
    ch("INSERT INTO webcat.stage_repair FORMAT JSONEachRow", "\n".join(json.dumps(r) for r, _ in rows).encode())
    repl, tmp, ids = "rekor-v1/repair.tmp.parquet", rel + ".tmp", ",".join(map(str, present))
    a = paths["archive"]; d = (a / rel).parent
    for stale in (a / repl, a / tmp):
        if stale.exists(): stale.unlink()  # a leftover from a failed run would be appended to, not replaced
    os.chmod(d, 0o755)  # archive directories are read-only between repairs; the temp file is written next to the original
    ch(f"INSERT INTO FUNCTION file({repl!r}, 'Parquet', {STRUCT!r}) SETTINGS engine_file_truncate_on_insert = 1, output_format_parquet_compression_method = 'zstd' "
       "SELECT LogIndex, IntegratedTime, Kind, unhex(EntryUUIDHex), IdentityGoType, '', Issuer, NotBefore, "
       "arrayMap(x -> (x.1, unhex(x.2), x.3), ExtHex), SANExtensionURIs, SANExtensionEmailAddresses, [], [] FROM webcat.stage_repair")
    ch(f"INSERT INTO FUNCTION file({tmp!r}, 'Parquet', {STRUCT!r}) SETTINGS engine_file_truncate_on_insert = 1, output_format_parquet_compression_method = 'zstd', "
       f"max_threads = 1, max_memory_usage = 1500000000, input_format_parquet_use_native_reader = 1 "
       f"SELECT * FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE NOT (LogIndex IN ({ids}) AND {PLACEHOLDER}) UNION ALL SELECT * FROM file({repl!r}, Parquet, {STRUCT!r})")
    old, new = (int(ch(f"SELECT count() FROM file({f!r}, Parquet) FORMAT TSV").strip()) for f in (rel, tmp))
    if new != old + len(absent): raise RuntimeError(f"{rel}: row count {old} -> {new}, expected {old + len(absent)}, not replacing")
    os.replace(a / tmp, a / rel); os.chmod(a / rel, 0o444); os.chmod(d, 0o555)
    replace_index_rows(present)
    subprocess.run(["clickhouse-client", f"--param_file={repl}", "--multiquery"], input=pathlib.Path(__file__).with_name("load_v1.sql").read_text(), text=True, check=True, capture_output=True)
    (a / repl).unlink()
    return len(present), sum(1 for _, ok in rows if ok)

def fill_missing(src, paths, indices):
    """Add entries the dataset never had (reported by the leaf-list check) to their export files. Returns how many were added."""
    url, added = src["url"].rstrip("/"), 0
    for rel, (lo, hi) in sorted(file_ranges(paths).items(), key=lambda kv: kv[1][0]):
        gaps = [i for i in indices if lo <= i <= hi]
        if gaps: added += repair_file(url, paths, rel, [], gaps)[0]
    return added

def repair(src, paths, budget=BUDGET):
    lock = open(LOCK, "w")
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError: logging.info("rekor-v1 repair: another repair run holds the queue, skipping"); return
    url = src["url"].rstrip("/")
    ranges = file_ranges(paths)
    queue = [int(x) for x in ch(f"SELECT DISTINCT log_index FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND issuer = '' AND kind NOT IN {NO_CERT_KINDS} ORDER BY log_index LIMIT {budget} FORMAT TSV").split()]
    missing_file = pathlib.Path("/srv/index/v1_missing.json")
    missing = json.loads(missing_file.read_text()) if missing_file.exists() else []   # from the leaf-list check: absent from the dataset
    logging.info("rekor-v1 repair: %d placeholder rows and %d missing entries queued (budget %d)", len(queue), len(missing), budget)
    fetched = fixed = files = 0
    for rel, (lo, hi) in sorted(ranges.items(), key=lambda kv: kv[1][0]):
        idxs = [i for i in queue if lo <= i <= hi]
        gaps = [i for i in missing if lo <= i <= hi]
        if not idxs and not gaps: continue
        n, k = repair_file(url, paths, rel, idxs, gaps)
        if n:
            fetched += n; fixed += k; files += 1
            logging.info("rekor-v1 repair: %s: %d rows replaced, %d given an identity (%d fetched so far)", rel, n, k, fetched)
    if missing: missing_file.unlink()  # fetched or confirmed unservable; the next leaf-list run re-reports what is still absent
    left = int(ch(f"SELECT count() FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND issuer = '' AND kind NOT IN {NO_CERT_KINDS}").strip() or 0)
    record_status("rekor-v1-repair", {"files_rewritten": files, "fetched": fetched, "repaired_this_run": fixed, "remaining": left})
    logging.info("rekor-v1 repair: %d files rewritten, %d entries given an identity, %d placeholder rows remaining", files, fixed, left)

if __name__ == "__main__":
    import sys, tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    src = next(s for s in cfg["source"] if s["type"] == "rekor-v1")
    if sys.argv[1:2] == ["sample"]: sample(src)
    elif sys.argv[1:2] == ["repair"]: repair(src, paths, int(sys.argv[2]) if len(sys.argv) > 2 else BUDGET)
    else: print("usage: quality.py sample | repair [budget]")

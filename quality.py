"""Rekor v1 content quality, since the dataset has no leaf bodies to hash:
- sample(): fetch random entries from the live log, confirm the leaf hash we hold, parse the certificate the way
  the v2 extractor does, compare identity, issuer and claims with the index.
- tail(): entries newer than the dataset, from the live log, until its next refresh catches up.
- repair(): entries the dataset left without an identity although they carry a certificate (~2.56M, mostly 2024
  DSSE) get it from the live log. The export file is rewritten in place in its own schema (temp file, rename), the
  file's rows are refreshed in the index. Entries with no certificate are marked IdentityGoType = "none" so they
  leave the queue. Rate-limited and resumable: the placeholder rows are the queue.
"""
import base64, fcntl, hashlib, json, logging, os, pathlib, random, subprocess, threading, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from rekor_v2 import record
from rekor_v1 import load_file
from util import ch, get, record_status

SAMPLE = 200
BUDGET = 60000              # entries per nightly repair run; the bootstrap backlog passes the full count
TAIL_BUDGET = 50000         # entries per tail round
TAIL_WORKERS = 20           # bulk retrieve answers 10 entries in ~10 s; this many in flight keeps RATE requests per second busy
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

def fetch_entries(url, idxs):
    """Live entries [(uuid, entry)] for up to 10 log indices in one request, at most RATE requests per second overall;
    waits through 429/503; indices the log will not serve are left out."""
    req = urllib.request.Request(f"{url}/api/v1/log/entries/retrieve", data=json.dumps({"logIndexes": list(idxs)}).encode(),
                                 headers={"User-Agent": "webcat-monitor (log auditor, contact: webcat@freedom.press)", "Content-Type": "application/json"})
    for n in range(200):
        with _gate:
            wait = _last[0] + 1.0 / RATE - time.monotonic()
            if wait > 0: time.sleep(wait)
            _last[0] = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return [next(iter(e.items())) for e in json.loads(r.read())]
        except urllib.error.HTTPError as e:
            if e.code in (429, 503): time.sleep(min(float(e.headers.get("Retry-After", 60)), 300)); continue
            if n >= 4: logging.warning("rekor-v1: %s: HTTP %d after %d tries, skipped", list(idxs), e.code, n + 1); return []
            time.sleep(2 ** n)
        except Exception as e:
            if n >= 9: logging.warning("rekor-v1: %s: %s, skipped", list(idxs), e); return []
            time.sleep(2 ** n)
    return []

def fetch_entry(url, idx): return next(iter(fetch_entries(url, [idx])), None)

def cert_from_body(body):
    """The signer certificate of a v1 entry body (hashedrekord, rekord, dsse, intoto), or None."""
    from cryptography import x509
    spec = body["spec"]
    pem = (spec.get("signature", {}).get("publicKey", {}).get("content") or (spec.get("signatures") or [{}])[0].get("verifier")
           or spec.get("publicKey") or spec.get("content", {}).get("publicKey"))
    if isinstance(pem, dict): pem = pem.get("content")   # alpine, rpm, helm: {"content": ...}
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

def stage_export(rows, archive, rel):
    """Rows in the export's own schema -> stage_repair -> a zstd Parquet file at archive/rel (replaced if present)."""
    ch("CREATE TABLE IF NOT EXISTS webcat.stage_repair (LogIndex Int64, IntegratedTime DateTime64(6, 'UTC'), Kind String, EntryUUIDHex String, "
       "IdentityGoType String, Issuer String, NotBefore DateTime64(6, 'UTC'), ExtHex Array(Tuple(String, String, Bool)), "
       "SANExtensionURIs Array(String), SANExtensionEmailAddresses Array(String)) ENGINE = Memory")
    ch("TRUNCATE TABLE webcat.stage_repair")
    ch("INSERT INTO webcat.stage_repair FORMAT JSONEachRow", "\n".join(json.dumps(r) for r in rows).encode())
    f = archive / rel
    f.parent.mkdir(parents=True, exist_ok=True); os.chmod(f.parent, 0o755)
    if f.exists(): f.unlink()
    ch(f"INSERT INTO FUNCTION file({rel!r}, 'Parquet', {STRUCT!r}) SETTINGS output_format_parquet_compression_method = 'zstd' "
       "SELECT LogIndex, IntegratedTime, Kind, unhex(EntryUUIDHex), IdentityGoType, '', Issuer, NotBefore, "
       "arrayMap(x -> (x.1, unhex(x.2), x.3), ExtHex), SANExtensionURIs, SANExtensionEmailAddresses, [], [] FROM webcat.stage_repair")

def tail(src, paths, budget=TAIL_BUDGET):
    """Entries newer than the archive holds, 10 per request from the live log, archived under rekor-v1/daily/live-<tag>/
    and loaded. The dataset's increments skip indices already held (load_v1.sql), so the two never overlap."""
    url = src["url"].rstrip("/")
    top = int(ch("SELECT log_index FROM webcat.leaves_v1 ORDER BY log_index DESC LIMIT 1 FORMAT TSV").strip() or 0)
    if not top: return 0
    info = json.loads(get(url + "/api/v1/log").decode())
    size = info["treeSize"] + sum(s["treeSize"] for s in info["inactiveShards"])
    idxs = range(top + 1, min(size, top + budget + 1))
    if not idxs: return 0
    with ThreadPoolExecutor(TAIL_WORKERS) as ex:
        fetched = [e for batch in ex.map(lambda b: fetch_entries(url, b), [idxs[i:i + 10] for i in range(0, len(idxs), 10)]) for e in batch]
    if not fetched: return 0
    rel = f"rekor-v1/daily/live-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}/part-000000000000.parquet"
    stage_export([export_row(u, v)[0] for u, v in fetched], paths["archive"], rel)
    f = paths["archive"] / rel; f.chmod(0o444); f.parent.chmod(0o555)
    load_file(rel)
    logging.info("rekor-v1 tail: %d entries %d..%d from the live log (log size %d)", len(fetched), idxs[0], idxs[-1], size)
    return len(fetched)

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

def replace_index_rows():
    """Drop every index row for the log indices now in stage_repair, each delete riding its table's key."""
    sub = "log_index IN (SELECT LogIndex FROM webcat.stage_repair)"
    rows = [json.loads(l) for l in ch(f"SELECT identity, toUnixTimestamp(time) AS t FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND {sub} FORMAT JSONEachRow").strip().split("\n") if l]
    if not rows: return
    lit = lambda x: "'" + x.replace("\\", "\\\\").replace("'", "\\'") + "'"
    idents = ",".join(lit(i) for i in {r["identity"] for r in rows}); times = ",".join(str(t) for t in {r["t"] for r in rows})
    ch(f"DELETE FROM webcat.entries WHERE identity IN ({idents}) AND log = 'rekor-v1' AND {sub}")
    ch(f"DELETE FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND {sub}")
    ch(f"DELETE FROM webcat.entries_by_time WHERE time IN ({times}) AND log = 'rekor-v1' AND {sub}")

PER_FILE = 5000

def repair_file(url, paths, rel, lo, hi, missing=()):
    """Replace up to PER_FILE placeholder rows of one export file within [lo, hi], and add rows for `missing` indices
    the dataset never had. Returns (entries fetched, entries given an identity). Serialized per file across callers."""
    with open(FILE_LOCK, "w") as fl:
        fcntl.flock(fl, fcntl.LOCK_EX)
        return _repair_file(url, paths, rel, lo, hi, missing)

def _repair_file(url, paths, rel, lo, hi, missing):
    present = [int(x) for x in ch(f"SELECT LogIndex FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE LogIndex BETWEEN {lo} AND {hi} AND {PLACEHOLDER} "
                                   f"AND ifNull(Kind, '') NOT IN {NO_CERT_KINDS} ORDER BY LogIndex LIMIT {PER_FILE} FORMAT TSV").split()] if lo <= hi else []
    absent = [i for i in missing if not ch(f"SELECT 1 FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE LogIndex = {i} LIMIT 1 FORMAT TSV").strip()]
    present = present + absent
    if not present: return 0, 0
    with ThreadPoolExecutor(WORKERS) as ex: fetched = [f for f in ex.map(lambda i: fetch_entry(url, i), present) if f]
    if not fetched: return 0, 0
    rows = [export_row(uuid, v) for uuid, v in fetched]
    repl, tmp = "rekor-v1/repair.tmp.parquet", rel + ".tmp"
    a = paths["archive"]; d = (a / rel).parent
    stage_export([r for r, _ in rows], a, repl)
    if (a / tmp).exists(): (a / tmp).unlink()
    os.chmod(d, 0o755)
    ch(f"INSERT INTO FUNCTION file({tmp!r}, 'Parquet', {STRUCT!r}) SETTINGS output_format_parquet_compression_method = 'zstd', "
       f"max_threads = 1, max_memory_usage = 1500000000, input_format_parquet_use_native_reader = 1 "
       f"SELECT * FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE NOT (LogIndex IN (SELECT LogIndex FROM webcat.stage_repair) AND {PLACEHOLDER}) "
       f"UNION ALL SELECT * FROM file({repl!r}, Parquet, {STRUCT!r})")
    old, new = (int(ch(f"SELECT count() FROM file({f!r}, Parquet) SETTINGS use_cache_for_count_from_files = 0 FORMAT TSV").strip()) for f in (rel, tmp))
    added = sum(1 for _, v in fetched if v["logIndex"] in absent)
    if new != old + added: raise RuntimeError(f"{rel}: row count {old} -> {new}, expected {old + added}, not replacing")
    os.replace(a / tmp, a / rel); os.chmod(a / rel, 0o444); os.chmod(d, 0o555)
    replace_index_rows()
    load_file(repl, reload=True)
    (a / repl).unlink()
    return len(fetched), sum(1 for _, ok in rows if ok)

def fill_missing(src, paths, indices):
    """Add entries the dataset never had (reported by the leaf-list check) to their export files. Returns how many were added."""
    url, added = src["url"].rstrip("/"), 0
    for rel, (lo, hi) in sorted(file_ranges(paths).items(), key=lambda kv: kv[1][0]):
        gaps = [i for i in indices if lo <= i <= hi]
        if gaps: added += repair_file(url, paths, rel, 1, 0, gaps)[0]
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
        if fetched >= budget: break
        idxs = [i for i in queue if lo <= i <= hi]
        gaps = [i for i in missing if lo <= i <= hi]
        if not idxs and not gaps: continue
        n, k = repair_file(url, paths, rel, min(idxs) if idxs else 1, max(idxs) if idxs else 0, gaps)
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
    elif sys.argv[1:2] == ["tail"]:   # service: keep the archive within minutes of the live log
        while True:
            n = tail(src, paths)
            if n: ch("INSERT INTO webcat.stats SELECT log, count(), max(time), now() FROM webcat.entries WHERE log = 'rekor-v1' GROUP BY log SETTINGS max_threads = 2")
            if n < TAIL_BUDGET: time.sleep(600)
    else: print("usage: quality.py sample | repair [budget] | tail")

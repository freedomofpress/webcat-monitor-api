"""Repair Rekor v1 export files in place. The dataset left ~2.56M entries (almost all 2024 DSSE) without an identity
although the entry carries a certificate. For each affected export file: fetch those entries from the live log,
build rows in the export's own schema, write the file anew with the placeholder rows replaced (temp file, rename),
refresh that file's rows in the index. Entries that truly have no certificate keep their row with IdentityGoType =
"none" so they leave the queue for good. One archive, one shape; the daily increment files get the same treatment.
Budget is in entries per run; a dedicated lock keeps the nightly run and a backlog run off the same files."""
import base64, fcntl, json, logging, os, pathlib, time, urllib.request
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from sample_v1 import cert_from_body
from util import ch, record_status

BUDGET = 60000
WORKERS = 2
RATE = 2.0                  # requests per second across workers; Rekor answered 429/503 at 3-9/s. ~170k entries/day.
_last = [0.0]; _gate = __import__("threading").Lock()
NO_CERT_KINDS = ("rfc3161", "tuf")
PLACEHOLDER = ("ifNull(Issuer, '') = '' AND length(Extensions) = 0 AND length(SANExtensionURIs) = 0 AND length(SANExtensionEmailAddresses) = 0 "
               "AND length(Digests) = 0 AND length(PGPIdentities) = 0 AND ifNull(IdentityGoType, '') != 'none'")
RANGES = pathlib.Path("/srv/index/v1_file_ranges.json")
DROP = {"1.3.6.1.4.1.11129.2.4.2", "2.5.29.14", "2.5.29.35", "2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.17"}  # as the export
STRUCT = ("LogIndex Nullable(Int64), IntegratedTime Nullable(DateTime64(6, 'UTC')), Kind Nullable(String), EntryUUID Nullable(String), "
          "IdentityGoType Nullable(String), ID Nullable(String), Issuer Nullable(String), NotBefore Nullable(DateTime64(6, 'UTC')), "
          "Extensions Array(Tuple(Key Nullable(String), Value Nullable(String), Critical Nullable(Bool))), SANExtensionURIs Array(String), "
          "SANExtensionEmailAddresses Array(String), Digests Array(String), PGPIdentities Array(String)")
STAGE = ("CREATE TABLE IF NOT EXISTS webcat.stage_repair (LogIndex Int64, IntegratedTime DateTime64(6, 'UTC'), Kind String, EntryUUIDHex String, "
         "IdentityGoType String, Issuer String, NotBefore DateTime64(6, 'UTC'), ExtHex Array(Tuple(String, String, Bool)), "
         "SANExtensionURIs Array(String), SANExtensionEmailAddresses Array(String)) ENGINE = Memory")

def fetch_entry(url, idx):
    req = urllib.request.Request(f"{url}/api/v1/log/entries?logIndex={idx}", headers={"User-Agent": "webcat-monitor (log auditor, contact: webcat@freedom.press)"})
    for n in range(200):  # 429/503 are Rekor asking for patience: wait and go on, up to ~3 hours for one entry
        with _gate:  # token-bucket-lite: one request per 1/RATE seconds across all workers
            wait = _last[0] + 1.0 / RATE - time.monotonic()
            if wait > 0: time.sleep(wait)
            _last[0] = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                uuid, v = next(iter(json.loads(r.read()).items())); return uuid, v
        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                time.sleep(min(float(e.headers.get("Retry-After", 60)), 300)); continue
            if n >= 9: raise
            time.sleep(2 ** n)
        except Exception:
            if n >= 9: raise
            time.sleep(2 ** n)
    raise RuntimeError(f"rekor-v1 repair: gave up fetching {idx}")

def export_row(uuid, v):
    """A row in the export's schema from a live entry; the certificate dissected the way the dataset does it."""
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
    """{relative file: [min LogIndex, max LogIndex]} for every v1 Parquet in the archive, from the Parquet footers; cached."""
    cached = json.loads(RANGES.read_text()) if RANGES.exists() else {}
    files = sorted(str(p.relative_to(paths["archive"])) for d in ("export/v1", "daily") for p in (paths["archive"] / "rekor-v1" / d).rglob("part-*.parquet"))
    for f in files:
        if f in cached: continue
        r = ch(f"SELECT arrayMin(arrayMap(rg -> toInt64OrNull(arrayFirst(c -> c.name = 'LogIndex', rg.columns).statistics.min), row_groups)), "
               f"arrayMax(arrayMap(rg -> toInt64OrNull(arrayFirst(c -> c.name = 'LogIndex', rg.columns).statistics.max), row_groups)) FROM file({f!r}, ParquetMetadata) FORMAT TSV").split()
        if "\\N" in r:  # no statistics in the footer: read the column
            r = ch(f"SELECT min(LogIndex), max(LogIndex) FROM file({f!r}, Parquet) SETTINGS max_threads = 1 FORMAT TSV").split()
        cached[f] = [int(r[0]), int(r[1])] if "\\N" not in r else None  # None: an empty file (a daily increment with no rows)
    RANGES.write_text(json.dumps(cached))
    return {f: v for f, v in cached.items() if f in files and v}

def replace_index_rows(indices):
    """Drop every index row for these v1 log indices, each delete riding its table's key."""
    ids = ",".join(map(str, indices))
    rows = [json.loads(l) for l in ch(f"SELECT identity, toUnixTimestamp(time) AS t FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index IN ({ids}) FORMAT JSONEachRow").strip().split("\n") if l]
    if not rows: return
    idents = ",".join("'" + r["identity"].replace("\\", "\\\\").replace("'", "\\'") + "'" for r in {r["identity"]: r for r in rows}.values())
    times = ",".join(str(r["t"]) for r in {r["t"]: r for r in rows}.values())
    ch(f"DELETE FROM webcat.entries WHERE identity IN ({idents}) AND log = 'rekor-v1' AND log_index IN ({ids})")
    ch(f"DELETE FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index IN ({ids})")
    ch(f"DELETE FROM webcat.entries_by_time WHERE time IN ({times}) AND log = 'rekor-v1' AND log_index IN ({ids})")

def repair_file(url, paths, rel, idxs):
    """Replace the placeholder rows of one export file. Returns (entries fetched, entries given an identity)."""
    present = [int(x) for x in ch(f"SELECT LogIndex FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE LogIndex IN ({','.join(map(str, idxs))}) AND {PLACEHOLDER} FORMAT TSV").split()]
    if not present: return 0, 0
    with ThreadPoolExecutor(WORKERS) as ex: fetched = list(ex.map(lambda i: fetch_entry(url, i), present))
    rows = [export_row(uuid, v) for uuid, v in fetched]
    fixed = sum(1 for _, ok in rows if ok)
    ch(STAGE); ch("TRUNCATE TABLE webcat.stage_repair")
    ch("INSERT INTO webcat.stage_repair FORMAT JSONEachRow", "\n".join(json.dumps(r) for r, _ in rows).encode())
    repl = "rekor-v1/repair.tmp.parquet"
    ch(f"INSERT INTO FUNCTION file({repl!r}, 'Parquet', {STRUCT!r}) SETTINGS engine_file_truncate_on_insert = 1, output_format_parquet_compression_method = 'zstd' "
       "SELECT LogIndex, IntegratedTime, Kind, unhex(EntryUUIDHex), IdentityGoType, '', Issuer, NotBefore, "
       "arrayMap(x -> (x.1, unhex(x.2), x.3), ExtHex), SANExtensionURIs, SANExtensionEmailAddresses, [], [] FROM webcat.stage_repair")
    tmp = rel + ".tmp"
    ids = ",".join(map(str, present))
    ch(f"INSERT INTO FUNCTION file({tmp!r}, 'Parquet', {STRUCT!r}) SETTINGS engine_file_truncate_on_insert = 1, output_format_parquet_compression_method = 'zstd', max_threads = 1, max_memory_usage = 1500000000, input_format_parquet_use_native_reader = 1 "
       f"SELECT * FROM file({rel!r}, Parquet, {STRUCT!r}) WHERE NOT (LogIndex IN ({ids}) AND {PLACEHOLDER}) "
       f"UNION ALL SELECT * FROM file({repl!r}, Parquet, {STRUCT!r})")
    old, new = (int(ch(f"SELECT count() FROM file({f!r}, Parquet) FORMAT TSV").strip()) for f in (rel, tmp))
    if old != new: raise RuntimeError(f"{rel}: row count changed {old} -> {new}, not replacing")
    a = paths["archive"]
    os.chmod(a / rel, 0o644); os.chmod((a / rel).parent, 0o755)
    os.replace(a / tmp, a / rel); os.chmod(a / rel, 0o444)
    replace_index_rows(present)
    import subprocess
    subprocess.run(["clickhouse-client", f"--param_file={repl}", "--multiquery"], input=pathlib.Path(__file__).with_name("load_v1.sql").read_text(), text=True, check=True, capture_output=True)
    (a / repl).unlink()
    return len(present), fixed

def run(src, paths, budget=BUDGET):
    lock = open("/run/lock/webcat-repair.lock", "w")
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logging.info("rekor-v1 repair: another repair run holds the queue, skipping"); return
    url = src["url"].rstrip("/")
    ranges = file_ranges(paths)
    q = f"SELECT DISTINCT log_index FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND issuer = '' AND kind NOT IN {NO_CERT_KINDS} ORDER BY log_index LIMIT {budget} FORMAT TSV"
    queue = [int(x) for x in ch(q).split()]
    logging.info("rekor-v1 repair: %d placeholder rows queued (budget %d)", len(queue), budget)
    fetched = fixed = files = 0
    for rel, (lo, hi) in sorted(ranges.items(), key=lambda kv: kv[1][0]):
        idxs = [i for i in queue if lo <= i <= hi]
        if not idxs: continue
        n, k = repair_file(url, paths, rel, idxs)
        if n:
            fetched += n; fixed += k; files += 1
            logging.info("rekor-v1 repair: %s: %d rows replaced, %d given an identity (%d fetched so far)", rel, n, k, fetched)
    left = int(ch(f"SELECT count() FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND issuer = '' AND kind NOT IN {NO_CERT_KINDS}").strip() or 0)
    record_status("rekor-v1-repair", {"files_rewritten": files, "fetched": fetched, "repaired_this_run": fixed, "remaining": left})
    logging.info("rekor-v1 repair: %d files rewritten, %d entries given an identity, %d placeholder rows remaining", files, fixed, left)

if __name__ == "__main__":
    import sys, tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    run(next(s for s in cfg["source"] if s["type"] == "rekor-v1"), paths, int(sys.argv[1]) if len(sys.argv) > 1 else BUDGET)

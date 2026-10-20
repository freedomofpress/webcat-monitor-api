"""Repair Rekor v1 rows the dataset left without an identity although the entry carries a certificate (2.56M
entries, almost all DSSE from 2024). Bodies come from the live log, 10 per request, within a per-run budget so a
nightly run stays polite; each batch is archived as our own Parquet chunk under rekor-v1/repaired/, fanned out to
every table, and the empty placeholder rows are removed. Resumable: the placeholder rows are the queue."""
import base64, hashlib, json, logging, pathlib, time, urllib.request
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from rekor_v2 import record, ARCHIVE_COLUMNS, write_archive, LOAD_SQL
from sample_v1 import cert_from_body
from util import ch, record_status

BUDGET = 60000              # entries per nightly run; the one-time backlog run passes the full count
CHUNK = 2000                # entries per archive file
WORKERS = 6                 # concurrent single-entry fetches: ~15 entries/s, the batch endpoint is slower per entry
NO_CERT_KINDS = ("rfc3161", "tuf")

def fetch_entry(url, idx):
    req = urllib.request.Request(f"{url}/api/v1/log/entries?logIndex={idx}", headers={"User-Agent": "webcat-monitor"})
    for n in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r: return next(iter(json.loads(r.read()).values()))
        except Exception:
            if n == 4: raise
            time.sleep(2 ** n)

def run(src, paths, budget=BUDGET):
    from concurrent.futures import ThreadPoolExecutor
    import fcntl
    lock = open("/run/lock/webcat-repair.lock", "w")
    try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logging.info("rekor-v1 repair: another repair run holds the queue, skipping"); return
    url = src["url"].rstrip("/")
    root = paths["archive"] / "rekor-v1" / "repaired"; root.mkdir(parents=True, exist_ok=True)
    q = f"SELECT DISTINCT log_index, toUnixTimestamp(time) FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND issuer = '' AND kind NOT IN {NO_CERT_KINDS} ORDER BY log_index LIMIT {budget} FORMAT TSV"
    when = {int(a): int(b) for a, b in (l.split("\t") for l in ch(q).strip().split("\n") if l)}
    queue = sorted(when)
    logging.info("rekor-v1 repair: %d placeholder rows queued (budget %d entries)", len(queue), budget)
    done = fixed = 0; resolved = []
    with ThreadPoolExecutor(WORKERS) as ex:
      for start in range(0, len(queue), CHUNK):
        batch = queue[start:start + CHUNK]
        rows = []
        for v in ex.map(lambda i: fetch_entry(url, i), batch):
            body = json.loads(base64.b64decode(v["body"]))
            cert = cert_from_body(body)
            t = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(v["integratedTime"]))
            resolved.append(v["logIndex"]); done += 1
            if cert:
                rows.append(record(v["logIndex"], t, body["kind"], {"x509Certificate": {"rawBytes": base64.b64encode(cert.public_bytes(Encoding.DER)).decode()}}, "")); fixed += 1
            else:  # no certificate in the log either: an explicit row (issuer "none") replaces the placeholder so it leaves the queue
                rows.append(record(v["logIndex"], t, body["kind"], {"keyDetails": "none", "publicKey": {"rawBytes": ""}}, ""))
        tag = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        archive = f"rekor-v1/repaired/{tag}-{batch[0]}.parquet"
        write_archive("rekor-v1", archive, rows); (paths["archive"] / archive).chmod(0o444)
        for stmt in LOAD_SQL: ch(stmt, params={"log": "rekor-v1", "file": archive})
        logging.info("rekor-v1 repair: %d entries fetched, %d repaired so far", done, fixed)
    # placeholders leave the queue in one delete per table, each riding its table's key
    if resolved:
        ids = ",".join(map(str, resolved)); times = ",".join(str(when[i]) for i in resolved if i in when)
        ch(f"DELETE FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND issuer = '' AND log_index IN ({ids})")
        ch(f"DELETE FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index IN ({ids}) AND identity = '' AND issuer = ''")
        if times: ch(f"DELETE FROM webcat.entries_by_time WHERE time IN ({times}) AND log = 'rekor-v1' AND identity = '' AND issuer = ''")
    left = int(ch(f"SELECT count() FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND issuer = '' AND kind NOT IN {NO_CERT_KINDS}").strip() or 0)
    record_status("rekor-v1-repair", {"repaired_this_run": fixed, "fetched": done, "remaining": left})
    logging.info("rekor-v1 repair: %d repaired this run, %d placeholder rows remaining", fixed, left)

if __name__ == "__main__":
    import sys, tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    run(next(s for s in cfg["source"] if s["type"] == "rekor-v1"), paths, int(sys.argv[1]) if len(sys.argv) > 1 else BUDGET)

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

BUDGET_REQUESTS = 6000      # x10 entries: ~60k entries per run, the backlog clears in ~6 weeks of nightly runs
BATCH_FILES = 50            # requests per archive chunk (500 entries)
NO_CERT_KINDS = ("rfc3161", "tuf")

def retrieve(url, idxs):
    req = urllib.request.Request(url + "/api/v1/log/entries/retrieve", data=json.dumps({"logIndexes": idxs}).encode(), headers={"content-type": "application/json", "User-Agent": "webcat-monitor"})
    for n in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r: return json.loads(r.read())
        except Exception:
            if n == 4: raise
            time.sleep(2 ** n)

def run(src, paths, budget=BUDGET_REQUESTS):
    url = src["url"].rstrip("/")
    root = paths["archive"] / "rekor-v1" / "repaired"; root.mkdir(parents=True, exist_ok=True)
    q = f"SELECT DISTINCT log_index, toUnixTimestamp(time) FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND kind NOT IN {NO_CERT_KINDS} ORDER BY log_index LIMIT {budget * 10} FORMAT TSV"
    when = {int(a): int(b) for a, b in (l.split("\t") for l in ch(q).strip().split("\n") if l)}
    queue = sorted(when)
    logging.info("rekor-v1 repair: %d placeholder rows queued (budget %d requests)", len(queue), budget)
    done = fixed = 0
    for start in range(0, len(queue), BATCH_FILES * 10):
        batch = queue[start:start + BATCH_FILES * 10]
        rows, resolved = [], []
        for i in range(0, len(batch), 10):
            for e in retrieve(url, batch[i:i + 10]):
                uuid, v = next(iter(e.items()))
                body = json.loads(base64.b64decode(v["body"]))
                cert = cert_from_body(body)
                resolved.append(v["logIndex"])
                if not cert: continue
                r = record(v["logIndex"], time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(v["integratedTime"])), body["kind"],
                           {"x509Certificate": {"rawBytes": base64.b64encode(cert.public_bytes(Encoding.DER)).decode()}}, "")
                rows.append(r); fixed += 1
            done += 1
        tag = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        archive = f"rekor-v1/repaired/{tag}-{batch[0]}.parquet"
        if rows:
            write_archive("rekor-v1", archive, rows); (paths["archive"] / archive).chmod(0o444)
            for stmt in LOAD_SQL: ch(stmt, params={"log": "rekor-v1", "file": archive})
        # the repaired (or confirmed certificate-less) placeholders leave the queue; each delete rides its table's key
        ids = ",".join(map(str, resolved)); times = ",".join(str(when[i]) for i in resolved if i in when)
        ch(f"DELETE FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND log_index IN ({ids})")
        ch(f"DELETE FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index IN ({ids}) AND identity = ''")
        if times: ch(f"DELETE FROM webcat.entries_by_time WHERE time IN ({times}) AND log = 'rekor-v1' AND identity = ''")
        logging.info("rekor-v1 repair: %d requests, %d entries repaired so far", done, fixed)
    left = int(ch(f"SELECT count() FROM webcat.entries WHERE identity = '' AND log = 'rekor-v1' AND kind NOT IN {NO_CERT_KINDS}").strip() or 0)
    record_status("rekor-v1-repair", {"repaired_this_run": fixed, "requests": done, "remaining": left})
    logging.info("rekor-v1 repair: %d repaired this run, %d placeholder rows remaining", fixed, left)

if __name__ == "__main__":
    import sys, tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    run(next(s for s in cfg["source"] if s["type"] == "rekor-v1"), paths, int(sys.argv[1]) if len(sys.argv) > 1 else BUDGET_REQUESTS)

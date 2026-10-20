"""Rekor v1 content spot check: the dataset has no leaf bodies, so the parsed fields in the index cannot be tied to
the leaves by hashing. Instead, each run fetches a random sample of entries from the live Rekor v1 API, hashes the
body to confirm the leaf hash we hold, parses the certificate the same way the v2 extractor does, and compares
identity, issuer and claims with the index rows. Mismatches are listed in the verification status."""
import base64, hashlib, json, logging, random
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from rekor_v2 import record, DROP
from util import ch, get, record_status

SAMPLE = 200

def cert_from_body(body):
    """The signer certificate of a v1 entry body, if it has one (hashedrekord, dsse, intoto)."""
    spec = body["spec"]
    pem = (spec.get("signature", {}).get("publicKey", {}).get("content")                       # hashedrekord, rekord
           or (spec.get("signatures") or [{}])[0].get("verifier")                               # dsse
           or spec.get("publicKey") or spec.get("content", {}).get("publicKey"))               # intoto
    if not pem: return None
    raw = base64.b64decode(pem)
    if b"BEGIN CERTIFICATE" not in raw: return None
    return x509.load_pem_x509_certificate(raw)

def check(src):
    url = src["url"].rstrip("/")
    rows = ch(f"SELECT log_index FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND rand() % 20000 = 0 LIMIT {SAMPLE * 3} SETTINGS max_threads = 2 FORMAT JSONEachRow")
    idxs = random.sample([int(json.loads(l)["log_index"]) for l in rows.strip().split("\n") if l], SAMPLE)
    problems, checked, with_cert = [], 0, 0
    for i in idxs:
        e = json.loads(get(f"{url}/api/v1/log/entries?logIndex={i}").decode())
        uuid, entry = next(iter(e.items()))
        body_b64 = entry["body"]; body = json.loads(base64.b64decode(body_b64))
        leaf = hashlib.sha256(b"\x00" + base64.b64decode(body_b64)).hexdigest()
        ours = ch(f"SELECT hex(leaf_hash) FROM webcat.leaves_v1 WHERE log_index = {i} LIMIT 1 FORMAT TSV").strip().lower()
        checked += 1
        if ours and ours != leaf: problems.append({"index": i, "what": "leaf hash", "index_has": ours, "log_has": leaf})
        if uuid[16:] != leaf: problems.append({"index": i, "what": "uuid vs body hash", "uuid": uuid, "body_hash": leaf})
        cert = cert_from_body(body)
        if not cert: continue
        with_cert += 1
        # same extraction as the v2 archive, then the same identity/issuer rules the index loaders apply
        r = record(i, "", body["kind"], {"x509Certificate": {"rawBytes": base64.b64encode(cert.public_bytes(Encoding.DER)).decode()}}, "")
        issuer = r["ext"].get("1.3.6.1.4.1.57264.1.8") or r["ext"].get("1.3.6.1.4.1.57264.1.1") or r["issuer_dn"]
        idents = set(r["san_uris"] + r["san_emails"] + r["san_other"])
        got = [json.loads(l) for l in ch(f"SELECT identity, issuer, ext FROM webcat.entries_by_index WHERE log = 'rekor-v1' AND log_index = {i} FORMAT JSONEachRow").strip().split("\n") if l]
        if not got: problems.append({"index": i, "what": "missing from the index"}); continue
        if idents and not idents & {g["identity"] for g in got}: problems.append({"index": i, "what": "identity", "index_has": [g["identity"] for g in got], "cert_has": sorted(idents)})
        if got[0]["issuer"] != issuer: problems.append({"index": i, "what": "issuer", "index_has": got[0]["issuer"], "cert_has": issuer})
        claims = {k: v for k, v in r["ext"].items() if k.startswith("1.3.6.1.4.1.57264.1.") and k.split(".")[-1] in ("2", "4", "5", "6", "9", "11", "12", "14", "16", "18", "20", "22", "23", "24")}
        bad = {k: (v, got[0]["ext"].get(k)) for k, v in claims.items() if got[0]["ext"].get(k) != v}
        if bad: problems.append({"index": i, "what": "claims", "diff": bad})
    result = {"sampled": checked, "with_certificate": with_cert, "problems": problems[:50], "problem_count": len(problems)}
    record_status("rekor-v1-sample", result)
    logging.log(logging.ERROR if problems else logging.INFO, "rekor-v1 sample: %d entries checked against the live log, %d with certificates, %d problems", checked, with_cert, len(problems))
    return problems

if __name__ == "__main__":
    import pathlib, tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    p = check(next(s for s in cfg["source"] if s["type"] == "rekor-v1"))
    for x in p[:10]: print(json.dumps(x)[:300])

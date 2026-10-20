#!/usr/bin/env python3
"""webcat log auditor API: read-only JSON over HTTP in front of the ClickHouse index and the Sigsum SQLite index.

  GET /v1/status
  GET /v1/sigstore/history?claims[<oid>]=<value>&claims[<oid>]=<value>...[&limit=N][&before=<unix time>]
      (OpenAPI deepObject style; values URL-encoded as usual)
  POST /v1/sigstore/history   body: {"claims": {<oid>: <value>, ...}, "limit": N, "before": <unix time>}
  GET /v1/sigsum/history?key=<hex sha256 of the signer public key>  |  ?signer=<base64url public key>
  GET /v1/entry/<log>/<log index>
  GET /v1/sha/<40 hex>          git commit SHA -> entries
  GET /v1/artifact/<64 hex>     artifact digest -> entries (Rekor v2 only)

Claim semantics are the extension's ClaimPolicy: every claim must match; a value starting with "^" is a prefix;
the SAN claim (2.5.29.17) matches any SAN. Queries run as the read-only ClickHouse user "api" whose profile caps
threads, memory and time; this process allows MAX_INFLIGHT queries at once and answers 503 beyond that.
"""
import base64, hashlib, json, pathlib, re, sqlite3, threading, tomllib, urllib.parse, urllib.request  # base64: sigsum signer keys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CH = "http://127.0.0.1:8123/?user=api&"
SIGSUM_DB = "/srv/index/sigsum.db"
PORT = 8080
MAX_INFLIGHT = 6
LIMIT, MAX_LIMIT = 500, 2000
OID_RE = re.compile(r"^[0-9]+(\.[0-9]+)+$")
SAN, ISSUER, ISSUER_V1 = "2.5.29.17", "1.3.6.1.4.1.57264.1.8", "1.3.6.1.4.1.57264.1.1"
# Claims that pin down a signer, most selective first: one of them drives the identity range of the query, the rest
# are checked on the certificate map inside that range. Driving from a low-selectivity claim (runner = github-hosted)
# would pull millions of identities through the claims table.
DRIVERS = ["1.3.6.1.4.1.57264.1.9", "1.3.6.1.4.1.57264.1.18", "1.3.6.1.4.1.57264.1.12", "1.3.6.1.4.1.57264.1.5",
           "1.3.6.1.4.1.57264.1.16", "1.3.6.1.4.1.57264.1.24", "1.3.6.1.4.1.57264.1.14", "1.3.6.1.4.1.57264.1.4"]
inflight = threading.BoundedSemaphore(MAX_INFLIGHT)
SOURCES = {s["name"]: s for s in tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())["source"]}

class Bad(Exception):
    def __init__(self, status, msg): self.status, self.msg = status, msg

def lit(s): return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
def match(expr, v): return f"startsWith({expr}, {lit(v[1:])})" if v.startswith("^") else f"{expr} = {lit(v)}"

def ch(sql):
    req = urllib.request.Request(CH + urllib.parse.urlencode({"query": sql + " FORMAT JSONEachRow", "default_format": "JSONEachRow"}))
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return [json.loads(l) for l in r.read().decode().split("\n") if l]
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise Bad(503 if "MEMORY_LIMIT" in body or "TIMEOUT" in body or "TOO_MANY" in body else 500, (re.search(r"Code: \d+\. [^\n]{0,160}", body) or [body[:160]])[0])

def history_sql(claims, limit, before):
    if not isinstance(claims, dict) or not claims or len(claims) > 16: raise Bad(400, "claims must be an object of 1 to 16 OID: value pairs")
    for k, v in claims.items():
        if not OID_RE.match(k) or not isinstance(v, str) or not 0 < len(v) <= 512: raise Bad(400, f"bad claim {k!r}")
    where = []
    driver = None if SAN in claims else next((o for o in DRIVERS if o in claims), next((o for o in claims if o not in (ISSUER, ISSUER_V1)), None))
    for oid, v in claims.items():
        if oid == SAN: where.append(match("identity", v))
        elif oid in (ISSUER, ISSUER_V1): where.append(match("issuer", v))
        else:
            if oid == driver:
                sub = f"startsWith(value, {lit(v[1:])})" if v.startswith("^") else f"value = {lit(v)}"
                where.append(f"identity IN (SELECT identity FROM webcat.claims WHERE oid = {lit(oid)} AND {sub})")
            where.append(f"has(mapKeys(ext), {lit(oid)}) AND {match(f'ext[{lit(oid)}]', v)}")
    if before: where.append(f"time < toDateTime({int(before)})")
    return (f"SELECT log, log_index, toUnixTimestamp(time) AS time, kind, issuer, identity, ext FROM webcat.entries "
            f"WHERE {' AND '.join(where)} ORDER BY time DESC LIMIT {limit}")

def with_links(rows):
    for r in rows:
        r["log_index"] = int(r["log_index"])
        if r["log"] == "rekor-v1": r["search_url"] = f"https://search.sigstore.dev/?logIndex={r['log_index']}"
    return rows

def route(path, qs, body=None):
    q = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
    if body:
        q.update({k: v for k, v in body.items() if k in ("limit", "before")})
    limit = min(int(q.get("limit", LIMIT)), MAX_LIMIT)
    parts = path.strip("/").split("/")
    if parts == ["v1", "status"]:
        logs = ch("SELECT log, entries, toUnixTimestamp(newest) AS newest, toUnixTimestamp(updated) AS updated FROM webcat.stats FINAL ORDER BY log")
        sigsum = sqlite3.connect(f"file:{SIGSUM_DB}?mode=ro", uri=True).execute("SELECT log, size, fetched_at FROM tree_heads").fetchall()
        return {"rekor": [{**r, "url": SOURCES.get(r["log"], {}).get("url")} for r in logs],
                "sigsum": [{"log": l, "url": SOURCES.get(l, {}).get("url"), "size": s, "fetched_at": t} for l, s, t in sigsum]}
    if parts == ["v1", "sigstore", "history"]:
        claims = body.get("claims") if body else {m.group(1): v[0] for k, v in urllib.parse.parse_qs(qs).items() if (m := re.match(r"^claims\[([0-9.]+)\]$", k))}
        if not claims: raise Bad(400, "no claims: pass claims[<oid>]=<value> query parameters, or POST {\"claims\": {...}}")
        rows = with_links(ch(history_sql(claims, limit, q.get("before"))))
        return {"claims": claims, "total": len(rows), "truncated": len(rows) == limit, "entries": rows}
    if parts == ["v1", "sigsum", "history"]:
        key = q.get("key") or (hashlib.sha256(base64.urlsafe_b64decode(q["signer"] + "=" * (-len(q["signer"]) % 4))).hexdigest() if q.get("signer") else None)
        if not key or not re.match(r"^[0-9a-f]{64}$", key): raise Bad(400, "key must be 64 hex chars, or pass signer=<base64url public key>")
        db = sqlite3.connect(f"file:{SIGSUM_DB}?mode=ro", uri=True)
        rows = db.execute("SELECT log, idx, hex(checksum) FROM leaves WHERE key_hash = ? ORDER BY log, idx LIMIT ?", (bytes.fromhex(key), limit)).fetchall()
        url = lambda l: SOURCES.get(l, {}).get("url", "").rstrip("/")
        return {"key_hash": key, "total": len(rows), "truncated": len(rows) == limit,
                "leaves": [{"log": l, "index": i, "checksum": c.lower(), "leaf_url": f"{url(l)}/get-leaves/{i}/{i + 1}" if url(l) else None} for l, i, c in rows]}
    if len(parts) == 4 and parts[:2] == ["v1", "entry"] and parts[3].isdigit():
        return {"entries": with_links(ch(f"SELECT DISTINCT log, log_index, toUnixTimestamp(time) AS time, kind, issuer, identity, ext FROM webcat.entries_by_index WHERE log = {lit(parts[2])} AND log_index = {int(parts[3])}"))}
    if len(parts) == 3 and parts[:2] == ["v1", "sha"] and re.match(r"^[0-9a-f]{40}$", parts[2]):
        return {"sha": parts[2], "entries": with_links(ch(f"SELECT DISTINCT e.log AS log, e.log_index AS log_index, toUnixTimestamp(e.time) AS time, e.kind AS kind, e.issuer AS issuer, e.identity AS identity FROM webcat.sha AS s INNER JOIN webcat.entries_by_index AS e USING (log, log_index) WHERE s.sha = unhex({lit(parts[2])}) LIMIT {limit}"))}
    if len(parts) == 3 and parts[:2] == ["v1", "artifact"] and re.match(r"^[0-9a-f]{64}$", parts[2]):
        return {"digest": parts[2], "entries": with_links(ch(f"SELECT DISTINCT e.log AS log, e.log_index AS log_index, toUnixTimestamp(e.time) AS time, e.kind AS kind, e.issuer AS issuer, e.identity AS identity FROM webcat.artifact AS a INNER JOIN webcat.entries_by_index AS e USING (log, log_index) WHERE a.digest = unhex({lit(parts[2])}) LIMIT {limit}"))}
    raise Bad(404, "unknown endpoint; see /v1/status, /v1/sigstore/history, /v1/sigsum/history, /v1/entry, /v1/sha, /v1/artifact")

class Handler(BaseHTTPRequestHandler):
    server_version = "webcat-auditor/0.1"
    def log_message(self, fmt, *args): pass
    def do_GET(self): self.handle_request(None)
    def do_POST(self):
        try: body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 65536)) or b"{}")
        except Exception: return self.reply(400, {"error": "body must be JSON"})
        self.handle_request(body if isinstance(body, dict) else {})
    def handle_request(self, body):
        u = urllib.parse.urlsplit(self.path)
        if not inflight.acquire(blocking=False):
            return self.reply(503, {"error": "busy, retry shortly"}, retry=2)
        try:
            self.reply(200, route(u.path, u.query, body))
        except Bad as e: self.reply(e.status, {"error": e.msg}, retry=2 if e.status == 503 else None)
        except Exception as e: self.reply(500, {"error": type(e).__name__})
        finally: inflight.release()
    def reply(self, status, obj, retry=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Cache-Control", "public, max-age=300")
        if retry: self.send_header("Retry-After", str(retry))
        self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

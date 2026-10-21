#!/usr/bin/env python3
"""webcat log auditor API: read-only JSON over HTTP in front of the ClickHouse index and the Sigsum SQLite index.

  GET /                 HTML: totals per log, API instructions
  GET /v1/status
  GET /v1/sigstore/history?claims[<oid>]=<value>&claims[<oid>]=<value>...[&limit=N][&before=<unix time>][&cursor=C]
      (OpenAPI deepObject style; values URL-encoded as usual)
  POST /v1/sigstore/history   body: {"claims": {<oid>: <value>, ...}, "limit": N, "before": <unix time>, "cursor": C}
  GET /v1/sigsum/history?key=<hex sha256 of the signer public key>  |  ?signer=<base64url public key>  [&cursor=C]
  Answers carry the real total; when truncated, "cursor" fetches the next page (opaque, pass it back as is).
  GET /v1/entry/<log>/<log index>
  GET /v1/sha/<40 hex>          git commit SHA -> entries
  GET /v1/artifact/<64 hex>     artifact digest -> entries (Rekor v2 only)

Claim semantics are the extension's: every claim must match, a value starting with "^" is a prefix, the SAN claim
matches any SAN. Queries run as the read-only ClickHouse user "api" (capped threads, memory, time); MAX_INFLIGHT
queries at once, a burst queues up to QUEUE_SECONDS, then 503.
"""
import base64, hashlib, html, json, pathlib, re, sqlite3, threading, time, tomllib, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CH = "http://127.0.0.1:8123/?user=api&"
SIGSUM_DB = "/srv/index/sigsum.db"
MAX_INFLIGHT = 8
QUEUE_SECONDS = 3
LIMIT, MAX_LIMIT = 500, 2000
OID_RE = re.compile(r"^[0-9]+(\.[0-9]+)+$")
SAN, ISSUER, ISSUER_V1 = "2.5.29.17", "1.3.6.1.4.1.57264.1.8", "1.3.6.1.4.1.57264.1.1"
# Selective claims, most selective first: one drives the identity range through the claims table, the rest are checked
# on the map inside that range. Driving from a broad claim (runner = github-hosted) would pull millions of identities.
DRIVERS = ["1.3.6.1.4.1.57264.1.9", "1.3.6.1.4.1.57264.1.18", "1.3.6.1.4.1.57264.1.12", "1.3.6.1.4.1.57264.1.5",
           "1.3.6.1.4.1.57264.1.16", "1.3.6.1.4.1.57264.1.24", "1.3.6.1.4.1.57264.1.14", "1.3.6.1.4.1.57264.1.4"]
inflight = threading.BoundedSemaphore(MAX_INFLIGHT)
CFG = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
SOURCES = {s["name"]: s for s in CFG["source"]}

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

def history_where(claims, before, cursor):
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
    if cursor:
        try: t, i, l = cursor.split(":", 2); t, i = int(t), int(i)
        except ValueError: raise Bad(400, "bad cursor")
        where.append(f"(time, log, log_index) < (toDateTime({t}), {lit(l)}, {i})")
    return " AND ".join(where)

def with_links(rows):
    for r in rows:
        r["log_index"] = int(r["log_index"])
        if r["log"] == "rekor-v1": r["search_url"] = f"https://search.sigstore.dev/?logIndex={r['log_index']}"
    return rows

def route(path, qs, body=None):
    q = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
    if body:
        q.update({k: v for k, v in body.items() if k in ("limit", "before", "cursor")})
    limit = min(int(q.get("limit", LIMIT)), MAX_LIMIT)
    parts = path.strip("/").split("/")
    if parts == ["v1", "status"]:
        logs = ch("SELECT log, entries, toUnixTimestamp(newest) AS newest, toUnixTimestamp(updated) AS updated FROM webcat.stats FINAL ORDER BY log")
        sigsum = sqlite3.connect(f"file:{SIGSUM_DB}?mode=ro", uri=True).execute("SELECT log, size, fetched_at FROM tree_heads").fetchall()
        vf = pathlib.Path("/srv/index/verification.json")
        return {"rekor": [{**r, "url": SOURCES.get(r["log"], {}).get("url")} for r in logs],
                "sigsum": [{"log": l, "url": SOURCES.get(l, {}).get("url"), "size": s, "fetched_at": t} for l, s, t in sigsum],
                "verification": json.loads(vf.read_text()) if vf.exists() else {}}
    if parts == ["v1", "sigstore", "history"]:
        claims = body.get("claims") if body else {m.group(1): v[0] for k, v in urllib.parse.parse_qs(qs).items() if (m := re.match(r"^claims\[([0-9.]+)\]$", k))}
        if not claims: raise Bad(400, "no claims: pass claims[<oid>]=<value> query parameters, or POST {\"claims\": {...}}")
        before, cursor = q.get("before"), q.get("cursor")
        rows = with_links(ch(f"SELECT log, log_index, toUnixTimestamp(time) AS time, kind, issuer, identity, ext FROM webcat.entries "
                             f"WHERE {history_where(claims, before, cursor)} ORDER BY time DESC, log DESC, log_index DESC LIMIT {limit}"))
        more = len(rows) == limit
        total = int(ch(f"SELECT count() AS n FROM webcat.entries WHERE {history_where(claims, before, None)}")[0]["n"]) if more or cursor else len(rows)
        return {"claims": claims, "total": total, "truncated": more, "cursor": f"{rows[-1]['time']}:{rows[-1]['log_index']}:{rows[-1]['log']}" if more else None, "entries": rows}
    if parts == ["v1", "sigsum", "history"]:
        key = q.get("key") or (hashlib.sha256(base64.urlsafe_b64decode(q["signer"] + "=" * (-len(q["signer"]) % 4))).hexdigest() if q.get("signer") else None)
        if not key or not re.match(r"^[0-9a-f]{64}$", key): raise Bad(400, "key must be 64 hex chars, or pass signer=<base64url public key>")
        db = sqlite3.connect(f"file:{SIGSUM_DB}?mode=ro", uri=True)
        try: cl, ci = q["cursor"].rsplit(":", 1) if q.get("cursor") else ("", -1); ci = int(ci)
        except ValueError: raise Bad(400, "bad cursor")
        rows = db.execute("SELECT log, idx, hex(checksum) FROM leaves WHERE key_hash = ? AND (log, idx) > (?, ?) ORDER BY log, idx LIMIT ?", (bytes.fromhex(key), cl, ci, limit)).fetchall()
        total = db.execute("SELECT count(*) FROM leaves WHERE key_hash = ?", (bytes.fromhex(key),)).fetchone()[0]
        url = lambda l: SOURCES.get(l, {}).get("url", "").rstrip("/")
        return {"key_hash": key, "total": total, "truncated": len(rows) == limit, "cursor": f"{rows[-1][0]}:{rows[-1][1]}" if len(rows) == limit else None,
                "leaves": [{"log": l, "index": i, "checksum": c.lower(), "leaf_url": f"{url(l)}/get-leaves/{i}/{i + 1}" if url(l) else None} for l, i, c in rows]}
    if len(parts) == 4 and parts[:2] == ["v1", "entry"] and parts[3].isdigit():
        return {"entries": with_links(ch(f"SELECT DISTINCT log, log_index, toUnixTimestamp(time) AS time, kind, issuer, identity, ext FROM webcat.entries_by_index WHERE log = {lit(parts[2])} AND log_index = {int(parts[3])}"))}
    if len(parts) == 3 and parts[:2] == ["v1", "sha"] and re.match(r"^[0-9a-f]{40}$", parts[2]):
        return {"sha": parts[2], "entries": with_links(ch(f"SELECT DISTINCT e.log AS log, e.log_index AS log_index, toUnixTimestamp(e.time) AS time, e.kind AS kind, e.issuer AS issuer, e.identity AS identity FROM webcat.sha AS s INNER JOIN webcat.entries_by_index AS e USING (log, log_index) WHERE s.sha = unhex({lit(parts[2])}) LIMIT {limit}"))}
    if len(parts) == 3 and parts[:2] == ["v1", "artifact"] and re.match(r"^[0-9a-f]{64}$", parts[2]):
        return {"digest": parts[2], "entries": with_links(ch(f"SELECT DISTINCT e.log AS log, e.log_index AS log_index, toUnixTimestamp(e.time) AS time, e.kind AS kind, e.issuer AS issuer, e.identity AS identity FROM webcat.artifact AS a INNER JOIN webcat.entries_by_index AS e USING (log, log_index) WHERE a.digest = unhex({lit(parts[2])}) LIMIT {limit}"))}
    raise Bad(404, "unknown endpoint; see /v1/status, /v1/sigstore/history, /v1/sigsum/history, /v1/entry, /v1/sha, /v1/artifact")

SOURCE_URL = "https://github.com/freedomofpress/webcat-monitor-api"
PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width"><title>WEBCAT log auditor</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:64em;margin:2em auto;padding:0 1em;color:#222}table{border-collapse:collapse}
td,th{text-align:left;padding:.25em 1.2em .25em 0;border-bottom:1px solid #ddd}pre{background:#f4f4f4;padding:.7em;overflow-x:auto}code{background:#f4f4f4;padding:.1em .3em}</style>
<h1>WEBCAT log auditor</h1>
<p><b>%(total)s</b> leaves indexed from %(n)d transparency logs, verified against their signed tree heads every half hour (Sigsum, Rekor v2) or nightly (Rekor v1).
Source code and documentation: <a href="%(src)s">%(src)s</a>.</p>
<table><tr><th>Log<th>Leaves<th>Newest leaf<th>Last update<th>Verification</tr>%(rows)s</table>
<h2>API</h2>
<p>Read-only JSON, no authentication, cached 5 minutes. Claim semantics are the WEBCAT extension's: every claim must match,
a value starting with <code>^</code> is a prefix, the SAN claim <code>2.5.29.17</code> matches any subject alternative name.
Please keep it to a few requests per second; a burst gets 503 with <code>Retry-After</code>.</p>
<pre>GET  /v1/sigstore/history?claims[&lt;oid&gt;]=&lt;value&gt;&amp;claims[&lt;oid&gt;]=&lt;value&gt;...[&amp;limit=N][&amp;before=&lt;unix time&gt;][&amp;cursor=C]
POST /v1/sigstore/history          {"claims": {"&lt;oid&gt;": "&lt;value&gt;", ...}, "limit": N, "before": &lt;unix time&gt;, "cursor": C}
GET  /v1/sigsum/history?signer=&lt;base64url public key&gt;   or   ?key=&lt;hex sha256 of the key&gt;   [&amp;cursor=C]
GET  /v1/entry/&lt;log&gt;/&lt;log index&gt;
GET  /v1/sha/&lt;40 hex git commit&gt;
GET  /v1/artifact/&lt;64 hex digest&gt;       Rekor v2 only
GET  /v1/status                          totals and last verification per log</pre>
<p>Examples</p>
<pre><a href="%(ex1)s">%(ex1)s</a>
<a href="%(ex2)s">%(ex2)s</a>
<a href="/v1/entry/rekor-v1/3081692656">/v1/entry/rekor-v1/3081692656</a>
<a href="/v1/status">/v1/status</a></pre>
<p>Entries carry <code>log</code>, <code>log_index</code>, <code>time</code>, <code>kind</code>, <code>issuer</code>, <code>identity</code> and
<code>ext</code> (the certificate's Fulcio OID claims); Rekor v1 entries link to search.sigstore.dev. Answers carry the real
<code>total</code>; limit is 500 by default, 2000 at most, and a truncated answer carries a <code>cursor</code> for the next page.</p>
"""

def home():
    st = route("/v1/status", "")
    day = lambda t: time.strftime("%Y-%m-%d %H:%M", time.gmtime(t)) if t else "-"
    def verdict(log):
        v = st["verification"].get(log)
        if not v: return "-"
        ok = all(x for x in v.values() if isinstance(x, bool)) and all(s.get("verified") for s in v.get("shards", {}).values())
        return ("verified " if ok else "FAILED ") + day(v["checked_at"])
    rows = [(r["log"], r["url"], r["entries"], day(r["newest"]), day(st["verification"].get(r["log"], {}).get("checked_at") or r["updated"]), verdict(r["log"])) for r in st["rekor"]]
    rows += [(s["log"], s["url"], s["size"], "-", day(s["fetched_at"]), verdict(s["log"])) for s in st["sigsum"]]
    tr = "".join(f'<tr><td><a href="{html.escape(u)}">{html.escape(l)}</a><td>{n:,}<td>{a}<td>{b}<td>{c}</tr>' for l, u, n, a, b, c in rows)
    ex1 = "/v1/sigstore/history?" + urllib.parse.urlencode({"claims[2.5.29.17]": "^https://github.com/freedomofpress/", "claims[1.3.6.1.4.1.57264.1.8]": "https://token.actions.githubusercontent.com", "limit": 20})
    ex2 = "/v1/sigsum/history?signer=wzRAXpRuYr5CHZmCAdK1Jh2widMU8GOwCNhONOHkV8k"
    return PAGE % {"total": f"{sum(r[2] for r in rows):,}", "n": len(rows), "src": SOURCE_URL, "rows": tr, "ex1": html.escape(ex1), "ex2": ex2}

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
        if not inflight.acquire(timeout=QUEUE_SECONDS):
            return self.reply(503, {"error": "busy, retry shortly"}, retry=2)
        try:
            if u.path == "/": self.reply(200, home(), ctype="text/html; charset=utf-8")
            else: self.reply(200, route(u.path, u.query, body))
        except Bad as e: self.reply(e.status, {"error": e.msg}, retry=2 if e.status == 503 else None)
        except Exception as e: self.reply(500, {"error": type(e).__name__})
        finally: inflight.release()
    def reply(self, status, obj, retry=None, ctype="application/json"):
        body = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*"); self.send_header("Cache-Control", "public, max-age=300")
        if retry: self.send_header("Retry-After", str(retry))
        self.end_headers(); self.wfile.write(body)

if __name__ == "__main__":
    ThreadingHTTPServer((CFG["api"]["bind"], CFG["api"]["port"]), Handler).serve_forever()

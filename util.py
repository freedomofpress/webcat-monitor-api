import json, pathlib, time, urllib.error, urllib.parse, urllib.request

class NotFound(Exception): pass

def get(url, timeout=120, tries=5):
    """GET with backoff; 404 raises NotFound at once."""
    for n in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "webcat-monitor"}), timeout=timeout) as r: return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404: raise NotFound(url)
            if n == tries - 1: raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if n == tries - 1: raise
        time.sleep(2 ** n)

def ch(query, data=None, params=None):
    """Local ClickHouse over HTTP. data: request body (INSERT ... FORMAT JSONEachRow); params: {name:Type} placeholders.
    Transient 5xx (memory, timeouts) are retried; syntax, unknown identifier and file errors are not."""
    q = {"query": query, **{"param_" + k: v for k, v in (params or {}).items()}}
    for n in range(20):
        try:
            with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8123/?" + urllib.parse.urlencode(q), data=data or None, method="POST"), timeout=600) as r:
                return r.read().decode()
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:400]
            if e.code < 500 or n == 19 or any(c in body for c in ("Code: 62", "Code: 47", "Code: 76")): raise RuntimeError(f"clickhouse {e.code}: {body}") from None
            time.sleep(30)

def record_status(name, status):
    """Merge one log's latest verification result into /srv/index/verification.json, served by /v1/status."""
    f = pathlib.Path("/srv/index/verification.json")
    d = json.loads(f.read_text()) if f.exists() else {}
    d[name] = {**status, "checked_at": int(time.time())}
    f.write_text(json.dumps(d, indent=1))

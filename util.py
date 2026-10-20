import time, urllib.error, urllib.request

class NotFound(Exception): pass

def get(url, timeout=120, tries=5):
    """GET with exponential backoff. 404 raises NotFound immediately, everything else retries."""
    for n in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "webcat-monitor"}), timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404: raise NotFound(url)
            if n == tries - 1: raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if n == tries - 1: raise
        time.sleep(2 ** n)

def ch(query, data=None, params=None):
    """Run a query on the local ClickHouse over HTTP. data = request body (e.g. JSONEachRow rows for an INSERT);
    params = values for {name:Type} placeholders in the query."""
    import urllib.parse
    q = {"query": query, **{"param_" + k: v for k, v in (params or {}).items()}}
    for n in range(20):  # the memory cap is shared with the v1 loader: a 5xx (usually MEMORY_LIMIT_EXCEEDED) is retried
        req = urllib.request.Request("http://127.0.0.1:8123/?" + urllib.parse.urlencode(q), data=data or None, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                return r.read().decode()
        except urllib.error.HTTPError as e:
            if e.code < 500 or n == 19: raise
            time.sleep(30)


def record_status(name, status):
    """Merge one log's latest verification result into /srv/index/verification.json (served by /v1/status)."""
    import json, pathlib, time
    f = pathlib.Path("/srv/index/verification.json")
    d = json.loads(f.read_text()) if f.exists() else {}
    d[name] = {**status, "checked_at": int(time.time())}
    f.write_text(json.dumps(d, indent=1))

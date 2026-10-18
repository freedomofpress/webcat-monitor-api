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

def merkle_root(hashes):
    """RFC 6962 tree hash over a list of node hashes. Also correct over 256-aligned subtree roots, see rekor_v2."""
    if len(hashes) == 1: return hashes[0]
    k = 1
    while k * 2 < len(hashes): k *= 2
    import hashlib
    return hashlib.sha256(b"\x01" + merkle_root(hashes[:k]) + merkle_root(hashes[k:])).digest()

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

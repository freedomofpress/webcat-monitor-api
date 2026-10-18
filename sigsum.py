"""Sigsum logs: every leaf goes into sqlite, indexed by signer key hash, and the local
leaves are rehashed against the log's tree head root on every run."""
import hashlib, logging, re, sqlite3
from util import get, merkle_root

BATCH = 4096  # logs cap this themselves and return fewer; the loop handles that

SCHEMA = """
CREATE TABLE IF NOT EXISTS leaves (log TEXT, idx INTEGER, key_hash BLOB, checksum BLOB, signature BLOB,
                                   PRIMARY KEY (log, idx)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS leaves_key ON leaves (key_hash, log, idx);
CREATE TABLE IF NOT EXISTS tree_heads (log TEXT PRIMARY KEY, size INTEGER, root_hash BLOB, raw TEXT, fetched_at INTEGER);
"""

def leaf_hash(checksum, signature, key_hash):
    return hashlib.sha256(b"\x00" + checksum + signature + key_hash).digest()

def fetch(src, paths):
    name, url = src["name"], src["url"].rstrip("/")
    db = sqlite3.connect(paths["index"] / "sigsum.db")
    db.executescript(SCHEMA)
    th = get(url + "/get-tree-head").decode()
    size = int(re.search(r"^size=(\d+)$", th, re.M)[1])
    root = bytes.fromhex(re.search(r"^root_hash=([0-9a-f]{64})$", th, re.M)[1])
    have = db.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM leaves WHERE log = ?", (name,)).fetchone()[0]
    i = have
    while i < size:
        text = get(f"{url}/get-leaves/{i}/{min(i + BATCH, size)}").decode()
        rows = [l[5:].split() for l in text.splitlines() if l.startswith("leaf=")]
        if not rows: raise RuntimeError(f"{name}: no leaves returned at {i}")
        db.executemany("INSERT OR REPLACE INTO leaves VALUES (?,?,?,?,?)",
                       [(name, i + j, bytes.fromhex(k), bytes.fromhex(c), bytes.fromhex(s)) for j, (c, s, k) in enumerate(rows)])
        i += len(rows)
    db.commit()
    # ponytail: full recompute each run, fine while logs are < ~10M leaves; cache subtree roots beyond that.
    hashes = [leaf_hash(c, s, k) for k, c, s in
              db.execute("SELECT key_hash, checksum, signature FROM leaves WHERE log = ? AND idx < ? ORDER BY idx", (name, size))]
    if len(hashes) != size or merkle_root(hashes) != root:
        raise RuntimeError(f"{name}: local leaves do not hash to the published root at size {size}")
    # ponytail: tree head signature and witness cosignatures are not checked (no ed25519 in the stdlib). Stored raw for later.
    db.execute("INSERT OR REPLACE INTO tree_heads VALUES (?,?,?,?,strftime('%s','now'))", (name, size, root, th))
    db.commit()
    logging.info("%s: %d leaves (+%d), root verified", name, size, size - have)

"""Sigsum logs: every leaf into SQLite, indexed by signer key hash; the leaves are rehashed to the signed tree head
root on every run, and the tree head signature and witness cosignatures are verified."""
import hashlib, logging, sqlite3
from util import get, record_status
from verify import merkle_root, verify_sigsum_tree_head

BATCH = 4096
SCHEMA = """
CREATE TABLE IF NOT EXISTS leaves (log TEXT, idx INTEGER, key_hash BLOB, checksum BLOB, signature BLOB, PRIMARY KEY (log, idx)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS leaves_key ON leaves (key_hash, log, idx);
CREATE TABLE IF NOT EXISTS tree_heads (log TEXT PRIMARY KEY, size INTEGER, root_hash BLOB, raw TEXT, fetched_at INTEGER);
"""

def leaf_hash(checksum, signature, key_hash):
    return hashlib.sha256(b"\x00" + checksum + signature + key_hash).digest()

def fetch(src, paths):
    name, url = src["name"], src["url"].rstrip("/")
    db = sqlite3.connect(paths["index"] / "sigsum.db"); db.executescript(SCHEMA)
    th = get(url + "/get-tree-head").decode()
    size, root, cosigs = verify_sigsum_tree_head(th, src["key"], paths.get("witnesses", {}))
    have = i = db.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM leaves WHERE log = ?", (name,)).fetchone()[0]
    while i < size:
        rows = [l[5:].split() for l in get(f"{url}/get-leaves/{i}/{min(i + BATCH, size)}").decode().splitlines() if l.startswith("leaf=")]
        if not rows: raise RuntimeError(f"{name}: no leaves returned at {i}")
        db.executemany("INSERT OR REPLACE INTO leaves VALUES (?,?,?,?,?)", [(name, i + j, bytes.fromhex(k), bytes.fromhex(c), bytes.fromhex(s)) for j, (c, s, k) in enumerate(rows)])
        i += len(rows)
    db.commit()
    hashes = [leaf_hash(c, s, k) for k, c, s in db.execute("SELECT key_hash, checksum, signature FROM leaves WHERE log = ? AND idx < ? ORDER BY idx", (name, size))]
    if len(hashes) != size or merkle_root(hashes) != root: raise RuntimeError(f"{name}: local leaves do not hash to the published root at size {size}")
    db.execute("INSERT OR REPLACE INTO tree_heads VALUES (?,?,?,?,strftime('%s','now'))", (name, size, root, th)); db.commit()
    record_status(name, {"size": size, "root": root.hex(), "leaves_hash_to_root": True, "log_signature": True, "cosignatures_verified": cosigs})
    logging.info("%s: %d leaves (+%d), root verified, log signature OK, %d cosignatures verified", name, size, size - have, cosigs)

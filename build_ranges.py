#!/usr/bin/env python3
"""One-time derivations from webcat.entries, walking the identity sort key in ranges small enough for DISTINCT or
re-sorting to fit in memory (adaptive prefix split). Each range is a key-range scan, so the table is read once per
target. Resumable: finished prefixes are logged per target.

Usage: build_ranges.py claims|by_index|by_time"""
import logging, pathlib, sys
from util import ch

MAX_ROWS = 40_000_000
SETTINGS = "SETTINGS max_threads = 2, max_memory_usage = 1500000000, max_bytes_before_external_sort = 800000000"
TARGETS = {
    "claims":   "INSERT INTO webcat.claims SELECT DISTINCT k, v, identity FROM webcat.entries ARRAY JOIN mapKeys(ext) AS k, mapValues(ext) AS v WHERE {where}",
    "by_index": "INSERT INTO webcat.entries_by_index SELECT * FROM webcat.entries WHERE log = 'rekor-v1' AND {where}",
    "by_time":  "INSERT INTO webcat.entries_by_time SELECT time, log, log_index, kind, issuer, identity FROM webcat.entries WHERE log = 'rekor-v1' AND {where}",
}
target = sys.argv[1]
SQL = TARGETS[target]
DONE = pathlib.Path(f"/srv/index/build_{target}.done")

def q(sql): return ch(sql).strip()

def build(prefix):
    if prefix in done: return
    n = int(q(f"SELECT count() FROM webcat.entries WHERE startsWith(identity, {prefix!r}) {SETTINGS}") or 0)
    if n == 0: return
    if n > MAX_ROWS and len(prefix) < 120:
        nxt = q(f"SELECT DISTINCT substring(identity, {len(prefix) + 1}, 1) AS c FROM webcat.entries WHERE startsWith(identity, {prefix!r}) AND length(identity) > {len(prefix)} ORDER BY c {SETTINGS} FORMAT TSVRaw")
        ch(SQL.format(where=f"identity = {prefix!r}") + " " + SETTINGS)   # identities equal to the prefix itself
        for c in nxt.split("\n"):
            if c != "": build(prefix + c)
    else:
        ch(SQL.format(where=f"startsWith(identity, {prefix!r})") + " " + SETTINGS)
        logging.info("%s: %r %d rows", target, prefix, n)
    with DONE.open("a") as f: f.write(prefix + "\n")
    done.add(prefix)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
done = set(DONE.read_text().split("\n")) if DONE.exists() else set()
build("")
logging.info("%s build complete", target)

#!/usr/bin/env python3
"""One-time build of webcat.claims from webcat.entries: distinct (oid, value, identity) triples.
Walks the identity sort key in ranges small enough for DISTINCT to fit in memory (adaptive prefix split),
so the whole 3.3B-row map is read exactly once as key-range scans. Resumable: finished prefixes are logged."""
import logging, pathlib, sys
from util import ch

MAX_ROWS = 40_000_000      # rows per DISTINCT chunk, keeps the hash set well under 1 GB
DONE = pathlib.Path("/srv/index/claims_build.done")
SETTINGS = "SETTINGS max_threads = 2, max_memory_usage = 1500000000"

def q(sql): return ch(sql).strip()

def count(prefix):
    return int(q(f"SELECT count() FROM webcat.entries WHERE startsWith(identity, {prefix!r}) {SETTINGS}") or 0)

def build(prefix):
    if prefix in done: return
    n = count(prefix)
    if n == 0: return
    if n > MAX_ROWS and len(prefix) < 120:
        nxt = q(f"SELECT DISTINCT substring(identity, {len(prefix) + 1}, 1) AS c FROM webcat.entries WHERE startsWith(identity, {prefix!r}) AND length(identity) > {len(prefix)} ORDER BY c {SETTINGS} FORMAT TSVRaw")
        # identities equal to the prefix itself (no next character) are handled by the exact-match insert below
        ch(f"INSERT INTO webcat.claims SELECT DISTINCT k, v, identity FROM webcat.entries ARRAY JOIN mapKeys(ext) AS k, mapValues(ext) AS v WHERE identity = {prefix!r} {SETTINGS}")
        for c in nxt.split("\n"):
            if c != "": build(prefix + c)
    else:
        ch(f"INSERT INTO webcat.claims SELECT DISTINCT k, v, identity FROM webcat.entries ARRAY JOIN mapKeys(ext) AS k, mapValues(ext) AS v WHERE startsWith(identity, {prefix!r}) {SETTINGS}")
        logging.info("claims: %r %d rows", prefix, n)
    with DONE.open("a") as f: f.write(prefix + "\n")
    done.add(prefix)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
done = set(DONE.read_text().split("\n")) if DONE.exists() else set()
build("")
logging.info("claims build complete")

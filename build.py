#!/usr/bin/env python3
"""Derived tables, built once from the loaded history (bootstrap) and appended by the daily loaders afterwards.
Every step is resumable through a done-list under /srv/index and bounded in memory: the identity-sorted main table is
walked in key ranges small enough for DISTINCT or re-sorting to fit.

usage: build.py keys-index | claims | by_index | by_time | sha | artifact | leaves | reproject <v2 source> | all"""
import logging, pathlib, subprocess, sys
from util import ch

MAX_ROWS = 40_000_000
S = "SETTINGS max_threads = 2, max_memory_usage = 1500000000, max_bytes_before_external_sort = 800000000"
FILE_S = "SETTINGS max_threads = 1, max_memory_usage = 1500000000, input_format_parquet_use_native_reader = 1, input_format_parquet_max_block_size = 4096"
ARCHIVE = pathlib.Path("/srv/archive")
RANGE_TARGETS = {
    "claims":   "INSERT INTO webcat.claims SELECT DISTINCT k, v, identity FROM webcat.entries ARRAY JOIN mapKeys(ext) AS k, mapValues(ext) AS v WHERE {where}",
    "by_index": "INSERT INTO webcat.entries_by_index SELECT * FROM webcat.entries WHERE log = 'rekor-v1' AND {where}",
    "by_time":  "INSERT INTO webcat.entries_by_time SELECT time, log, log_index, kind, issuer, identity FROM webcat.entries WHERE log = 'rekor-v1' AND {where}",
}
FILE_TARGETS = {  # per archive file: (glob, SQL with {f})
    "sha": [("rekor-v1/export/v1/part-*.parquet", "INSERT INTO webcat.sha SELECT DISTINCT unhex(h), 'rekor-v1', toUInt64(LogIndex) FROM file({f!r}, Parquet) "
             "ARRAY JOIN arrayMap(x -> ifNull(x.2, ''), arrayFilter(x -> x.1 IN ('1.3.6.1.4.1.57264.1.3', '1.3.6.1.4.1.57264.1.13'), Extensions)) AS h "
             "WHERE LogIndex IS NOT NULL AND length(h) = 40 AND match(h, '^[0-9a-f]{{40}}$')"),
            ("rekor-v2/*/parsed/*.parquet", "INSERT INTO webcat.sha SELECT DISTINCT unhex(h), {log!r}, log_index FROM file({f!r}, Parquet) "
             "ARRAY JOIN [ext['1.3.6.1.4.1.57264.1.3'], ext['1.3.6.1.4.1.57264.1.13']] AS h WHERE length(h) = 40 AND match(h, '^[0-9a-f]{{40}}$')")],
    "artifact": [("rekor-v2/*/parsed/*.parquet", "INSERT INTO webcat.artifact SELECT DISTINCT unhex(artifact_digest), {log!r}, log_index FROM file({f!r}, Parquet) WHERE length(artifact_digest) = 64")],
    "leaves": [("rekor-v1/export/v1/part-*.parquet", "INSERT INTO webcat.leaves_v1 SELECT DISTINCT toUInt64(LogIndex), left(hex(EntryUUID), 16), substring(EntryUUID, 9, 32) "
                "FROM file({f!r}, Parquet) WHERE LogIndex IS NOT NULL AND length(EntryUUID) = 40"),
               ("rekor-v1/daily/*/part-*.parquet", "INSERT INTO webcat.leaves_v1 SELECT DISTINCT toUInt64(LogIndex), left(hex(EntryUUID), 16), substring(EntryUUID, 9, 32) "
                "FROM file({f!r}, Parquet) WHERE LogIndex IS NOT NULL AND length(EntryUUID) = 40")],
}

def done_list(name):
    p = pathlib.Path(f"/srv/index/build_{name}.done"); p.touch()
    return p, set(p.read_text().split("\n"))

def by_ranges(target):
    """Walk the identity key adaptively: a prefix with more than MAX_ROWS rows is split by its next character."""
    done_file, done = done_list(target); sql = RANGE_TARGETS[target]
    def build(prefix):
        if prefix in done: return
        n = int(ch(f"SELECT count() FROM webcat.entries WHERE startsWith(identity, {prefix!r}) {S}") or 0)
        if n == 0: return
        if n > MAX_ROWS and len(prefix) < 120:
            ch(sql.format(where=f"identity = {prefix!r}") + " " + S)
            for c in ch(f"SELECT DISTINCT substring(identity, {len(prefix) + 1}, 1) AS c FROM webcat.entries WHERE startsWith(identity, {prefix!r}) AND length(identity) > {len(prefix)} ORDER BY c {S} FORMAT TSVRaw").split("\n"):
                if c != "": build(prefix + c)
        else:
            ch(sql.format(where=f"startsWith(identity, {prefix!r})") + " " + S)
            logging.info("%s: %r %d rows", target, prefix, n)
        with done_file.open("a") as f: f.write(prefix + "\n")
        done.add(prefix)
    build("")

def by_files(target):
    done_file, done = done_list(target)
    for glob, sql in FILE_TARGETS[target]:
        for p in sorted(ARCHIVE.glob(glob)):
            rel = str(p.relative_to(ARCHIVE))
            if rel in done: continue
            log = rel.split("/")[1] if rel.startswith("rekor-v2/") else "rekor-v1"
            ch(sql.format(f=rel, log=log) + " " + FILE_S)
            with done_file.open("a") as f: f.write(rel + "\n")
    logging.info("%s: complete", target)

def keys_index():
    ch("ALTER TABLE webcat.entries MATERIALIZE INDEX ext_keys SETTINGS mutations_sync = 2")
    logging.info("keys index materialized")

def reproject(name):
    """Re-derive one v2 source's rows in entries, entries_by_index and entries_by_time from its archive (projection change)."""
    for t in ("entries", "entries_by_index", "entries_by_time"): ch(f"DELETE FROM webcat.{t} WHERE log = {name!r}")
    stmts = [q for q in pathlib.Path(__file__).with_name("load_v2.sql").read_text().split(";\n") if "stage_v2" in q][:5]
    for p in sorted((ARCHIVE / "rekor-v2" / name / "parsed").glob("*.parquet")):
        subprocess.run(["clickhouse-client", f"--param_log={name}", f"--param_file={p.relative_to(ARCHIVE)}", "--multiquery"], input=";\n".join(stmts) + ";", text=True, check=True, capture_output=True)
    logging.info("%s: re-projected", name)

def finish():
    for t in ("claims", "sha", "artifact"): ch(f"OPTIMIZE TABLE webcat.{t} FINAL")
    ch("INSERT INTO webcat.stats SELECT log, count(), max(time), now() FROM webcat.entries GROUP BY log SETTINGS max_threads = 2")
    print(ch("SELECT table, sum(rows) AS rows, formatReadableSize(sum(bytes_on_disk)) AS size FROM system.parts WHERE active AND database = 'webcat' GROUP BY table ORDER BY table FORMAT PrettyCompactNoEscapes"))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    step = sys.argv[1] if len(sys.argv) > 1 else "all"
    if step == "all":
        keys_index()
        for t in RANGE_TARGETS: by_ranges(t)
        for t in FILE_TARGETS: by_files(t)
        finish()
    elif step == "keys-index": keys_index()
    elif step in RANGE_TARGETS: by_ranges(step)
    elif step in FILE_TARGETS: by_files(step)
    elif step == "reproject": reproject(sys.argv[2])
    elif step == "finish": finish()
    else: sys.exit(__doc__)

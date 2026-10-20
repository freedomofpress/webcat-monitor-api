#!/usr/bin/env python3
"""webcat-monitor: mirror the transparency logs WEBCAT trusts and index what matters.

usage: monitor.py [-c sources.toml] [NAME ...]     (no NAME = every source)

Each [[source]] in the config has a `type`; FETCHERS maps a type to one function that brings the
local copy up to date and verifies it. New instance = config block. New log type = one function here.
"""
import argparse, logging, pathlib, sys, tomllib
import rekor_v1, rekor_v2, sigsum

def rekor_v1_fetch_and_verify(src, paths):
    rekor_v1.fetch(src, paths)
    import verify_v1, sample_v1
    verify_v1.run(src)  # extends the per-shard Merkle frontiers over the new leaves and checks them against the signed tree heads
    sample_v1.check(src)  # random entries fetched from the live log: leaf hash and parsed fields vs the index

FETCHERS = {"sigsum": sigsum.fetch, "rekor-v2": rekor_v2.fetch, "rekor-v1": rekor_v1_fetch_and_verify}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default=pathlib.Path(__file__).with_name("sources.toml"))
    ap.add_argument("names", nargs="*")
    ap.add_argument("--rewrite-archive", type=int, metavar="UNTIL_BUNDLE", help="rekor-v2 only: refetch bundles [0, N) and rewrite their archive chunks")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(a.config).read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    import hashlib
    paths["witnesses"] = {hashlib.sha256(bytes.fromhex(k)).hexdigest(): k for k in cfg.get("witnesses", {}).values()}  # key hash -> key
    failed = 0
    for src in cfg["source"]:
        if a.names and src["name"] not in a.names: continue
        try:
            if a.rewrite_archive is not None:
                if src["type"] == "rekor-v2": rekor_v2.rewrite_archive(src, paths, a.rewrite_archive)
                continue
            FETCHERS[src["type"]](src, paths)
        except Exception:
            logging.exception("%s failed", src["name"]); failed += 1
    if not a.names and not failed:  # a full run: refresh the per-log totals the API's status endpoint serves
        from util import ch
        ch("INSERT INTO webcat.stats SELECT log, count(), max(time), now() FROM webcat.entries GROUP BY log SETTINGS max_threads = 2")
    sys.exit(1 if failed else 0)

if __name__ == "__main__": main()

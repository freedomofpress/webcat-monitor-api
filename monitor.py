#!/usr/bin/env python3
"""Daily entry point: bring every source up to date, verify it, refresh the totals.
usage: monitor.py [-c sources.toml] [NAME ...]   (no NAME = every source)"""
import argparse, hashlib, logging, pathlib, sys, tomllib
import quality, rekor_v1, rekor_v2, sigsum, verify
from util import ch

def rekor_v1_daily(src, paths):
    rekor_v1.fetch(src, paths)
    verify.rekor_v1_leaves(src, paths)
    quality.sample(src)
    quality.repair(src, paths)

FETCHERS = {"sigsum": sigsum.fetch, "rekor-v2": rekor_v2.fetch, "rekor-v1": rekor_v1_daily}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default=pathlib.Path(__file__).with_name("sources.toml"))
    ap.add_argument("names", nargs="*")
    ap.add_argument("--rewrite-archive", type=int, metavar="UNTIL_BUNDLE", help="rekor-v2 only: refetch bundles [0, N) and rewrite their archive chunks")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(a.config).read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    paths["witnesses"] = {hashlib.sha256(bytes.fromhex(k)).hexdigest(): k for k in cfg.get("witnesses", {}).values()}
    failed = 0
    for src in cfg["source"]:
        if a.names and src["name"] not in a.names: continue
        src["_cfg"] = cfg
        try:
            if a.rewrite_archive is not None:
                if src["type"] == "rekor-v2": rekor_v2.rewrite_archive(src, paths, a.rewrite_archive)
                continue
            FETCHERS[src["type"]](src, paths)
        except Exception:
            logging.exception("%s failed", src["name"]); failed += 1
    if not a.names and not failed:
        ch("INSERT INTO webcat.stats SELECT log, count(), max(time), now() FROM webcat.entries GROUP BY log SETTINGS max_threads = 2")
    sys.exit(1 if failed else 0)

if __name__ == "__main__": main()

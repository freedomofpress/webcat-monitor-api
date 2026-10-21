#!/usr/bin/env python3
"""Entry point: bring every source up to date, verify it, refresh its totals. Sigsum and Rekor v2 run every half hour,
Rekor v1 nightly (systemd timers).
usage: monitor.py [-c sources.toml] [-t TYPE ...] [NAME ...]   (no NAME, no TYPE = every source)"""
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
    ap.add_argument("-t", "--type", action="append", default=[], help="only sources of this type (repeatable)")
    ap.add_argument("--rewrite-archive", type=int, metavar="UNTIL_BUNDLE", help="rekor-v2 only: refetch bundles [0, N) and rewrite their archive chunks")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(a.config).read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    paths["witnesses"] = {hashlib.sha256(bytes.fromhex(k)).hexdigest(): k for k in cfg.get("witnesses", {}).values()}
    failed = 0
    for src in cfg["source"]:
        if a.names and src["name"] not in a.names or a.type and src["type"] not in a.type: continue
        src["_cfg"] = cfg
        try:
            if a.rewrite_archive is not None:
                if src["type"] == "rekor-v2": rekor_v2.rewrite_archive(src, paths, a.rewrite_archive)
                continue
            FETCHERS[src["type"]](src, paths)
            if src["type"] != "sigsum":
                ch(f"INSERT INTO webcat.stats SELECT log, count(), max(time), now() FROM webcat.entries WHERE log = {src['name']!r} GROUP BY log SETTINGS max_threads = 2")
        except Exception:
            logging.exception("%s failed", src["name"]); failed += 1
    sys.exit(1 if failed else 0)

if __name__ == "__main__": main()

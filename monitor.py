#!/usr/bin/env python3
"""webcat-monitor: mirror the transparency logs WEBCAT trusts and index what matters.

usage: monitor.py [-c sources.toml] [NAME ...]     (no NAME = every source)

Each [[source]] in the config has a `type`; FETCHERS maps a type to one function that brings the
local copy up to date and verifies it. New instance = config block. New log type = one function here.
"""
import argparse, logging, pathlib, sys, tomllib
import rekor_v2, sigsum

def rekor_v1(src, paths):
    # ponytail: v1 has no bulk read API. History comes from the BigQuery export, the tail from APPENDS. Not wired yet.
    logging.warning("%s: rekor v1 fetch not implemented, skipping", src["name"])

FETCHERS = {"sigsum": sigsum.fetch, "rekor-v2": rekor_v2.fetch, "rekor-v1": rekor_v1}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config", default=pathlib.Path(__file__).with_name("sources.toml"))
    ap.add_argument("names", nargs="*")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(a.config).read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    failed = 0
    for src in cfg["source"]:
        if a.names and src["name"] not in a.names: continue
        try:
            FETCHERS[src["type"]](src, paths)
        except Exception:
            logging.exception("%s failed", src["name"]); failed += 1
    sys.exit(1 if failed else 0)

if __name__ == "__main__": main()

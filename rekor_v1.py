"""Rekor v1 through Google's BigQuery dataset (the v1 API serves one entry per request; the log has 3.3B).
- fetch(): the daily increment. APPENDS() on the public tables returns only rows added since the previous run
  (~16 GB scanned per day, inside the free tier), exported as ZSTD Parquet, pulled into the archive, loaded by
  load_v1.sql. The dataset trails the live log by days; APPENDS reaches back 7 days, so a gap over 6 days fails
  loudly instead of silently costing a full scan.
- export(): the one-time history export (~4 TB scanned, ~25 USD, plus egress), resumable through the bucket.
- load_history(): pull the export from the bucket, verify it against the bucket listing, make it read-only, load
  every file atomically (staging table, attach), resumable through a done-list.
The export query: Entries LEFT JOIN Identities (every leaf, identity fields null where the loader has none), the
raw SAN kept where the loader's SAN columns are empty, Identities.ID dropped (a random row uuid)."""
import datetime, json, logging, os, pathlib, subprocess
from util import ch

EXPORT_SQL = """
SELECT e.LogIndex, e.IntegratedTime, e.Kind,
       COALESCE(SAFE.FROM_HEX(e.EntryUUID), CAST(e.EntryUUID AS BYTES)) AS EntryUUID,
       i.IdentityGoType, i.Issuer, i.NotBefore,
       ARRAY(SELECT AS STRUCT x.Key, COALESCE(SAFE.FROM_BASE64(x.Value), CAST(x.Value AS BYTES)) AS Value, x.Critical
             FROM UNNEST(i.Extensions) x
             WHERE x.Key NOT IN ('1.3.6.1.4.1.11129.2.4.2','2.5.29.14','2.5.29.35','2.5.29.15','2.5.29.37','2.5.29.19')
               AND (x.Key <> '2.5.29.17' OR (ARRAY_LENGTH(i.SANExtensionURIs) = 0 AND ARRAY_LENGTH(i.SANExtensionEmailAddresses) = 0))) AS Extensions,
       i.SANExtensionURIs, i.SANExtensionEmailAddresses,
       IF(i.Issuer LIKE '%sigstore.dev%', [], i.Digests) AS Digests,
       i.PGPIdentities
FROM {entries} e
LEFT JOIN {identities} i USING (EntryUUID)"""
ARTIFACTS_SQL = "SELECT EntryUUID, Digest, AttestationType, SubjectName FROM `bigquery-public-data.rekor.Artifacts`"
MAX_GAP_DAYS = 6

def gcp(cfg):
    g = cfg["gcp"]
    env = {**os.environ, "CLOUDSDK_CONFIG": g["credentials"], "HOME": g["credentials"]}
    def run(*cmd):
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if r.returncode: raise RuntimeError(f"{cmd[0]} failed: {(r.stderr or r.stdout).strip()[-400:]}")
        return r.stdout
    bq = lambda *a: run("bq", f"--project_id={g['project']}", "--location=US", *a)
    return g, run, bq

def load_file(rel, reload=False):
    """Load one v1 Parquet file through load_v1.sql (stage table, fan-out to every table). Log indices the index
    already holds are skipped unless reload (the repair, which drops them first)."""
    lo, hi = ch(f"SELECT ifNull(min(LogIndex), 0), ifNull(max(LogIndex), 0) FROM file({rel!r}, Parquet) FORMAT TSV").split()
    subprocess.run(["clickhouse-client", f"--param_file={rel}", f"--param_lo={lo}", f"--param_hi={hi}", f"--param_reload={int(reload)}", "--multiquery"],
                   input=pathlib.Path(__file__).with_name("load_v1.sql").read_text(), text=True, check=True, capture_output=True)

def fetch(src, paths):
    """Daily increment."""
    g, run, bq = gcp(src["_cfg"])
    root = paths["archive"] / "rekor-v1" / "daily"; root.mkdir(parents=True, exist_ok=True)
    state_file = root / "state.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {"since": g["export_snapshot"]}
    since = datetime.datetime.fromisoformat(state["since"].replace("Z", "+00:00"))
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    if (now - since).days > MAX_GAP_DAYS:
        raise RuntimeError(f"rekor-v1: last increment {state['since']} is over {MAX_GAP_DAYS} days old; APPENDS cannot reach back, decide on a re-export")
    tag = now.strftime("%Y%m%dT%H%M%SZ"); table = f"{g['dataset']}.v1_daily_{tag}"; prefix = f"{g['bucket']}/v1_daily/{tag}"
    sql = EXPORT_SQL.format(entries=f"APPENDS(TABLE `bigquery-public-data.rekor.Entries`, TIMESTAMP '{since.isoformat()}', TIMESTAMP '{now.isoformat()}')",
                            identities=f"APPENDS(TABLE `bigquery-public-data.rekor.Identities`, TIMESTAMP '{since.isoformat()}', TIMESTAMP '{now.isoformat()}')")
    bq("query", "--use_legacy_sql=false", "--format=none", f"--destination_table={table}", "--replace", "--maximum_bytes_billed=200000000000", sql)
    bq("extract", "--destination_format=PARQUET", "--compression=ZSTD", table, f"{prefix}/part-*.parquet")
    local = root / tag; local.mkdir(exist_ok=True)
    run("gcloud", "storage", "rsync", "-r", f"{prefix}/", str(local) + "/")
    rows = 0
    for f in sorted(local.glob("part-*.parquet")):
        f.chmod(0o444); rel = str(f.relative_to(paths["archive"]))
        rows += int(ch(f"SELECT count() FROM file({rel!r}, Parquet)").strip() or 0); load_file(rel)
    run("gcloud", "storage", "rm", "-r", prefix); bq("rm", "-f", "-t", table)
    state.update({"since": now.isoformat().replace("+00:00", "Z"), "last_rows": rows})
    state_file.write_text(json.dumps(state))
    logging.info("rekor-v1: +%d rows for %s .. %s", rows, since.isoformat(), now.isoformat())

def export(cfg):
    """One-time history export into the bucket. Record the start time as gcp.export_snapshot in sources.toml."""
    g, run, bq = gcp(cfg)
    bq("mk", "-f", "--dataset", g["dataset"])
    print("snapshot time (put it in sources.toml as gcp.export_snapshot):", datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat())
    bq("query", "--use_legacy_sql=false", "--format=none", f"--destination_table={g['dataset']}.v1", "--replace", "--clustering_fields=LogIndex",
       "--maximum_bytes_billed=4500000000000", EXPORT_SQL.format(entries="`bigquery-public-data.rekor.Entries`", identities="`bigquery-public-data.rekor.Identities`"))
    bq("query", "--use_legacy_sql=false", "--format=none", f"--destination_table={g['dataset']}.v1_artifacts", "--replace", "--maximum_bytes_billed=100000000000", ARTIFACTS_SQL)
    run("gcloud", "storage", "buckets", "create", g["bucket"], f"--project={g['project']}", "--location=US", "--uniform-bucket-level-access")
    for t in ("v1", "v1_artifacts"):
        bq("extract", "--destination_format=PARQUET", "--compression=ZSTD", f"{g['dataset']}.{t}", f"{g['bucket']}/{t}/part-*.parquet")
        bq("rm", "-f", "-t", f"{g['dataset']}.{t}")
    print(run("gcloud", "storage", "du", "-s", g["bucket"]))

def load_history(cfg, paths):
    """Pull the export from the bucket once, verify, freeze, load every file atomically."""
    g, run, bq = gcp(cfg)
    dst = paths["archive"] / "rekor-v1" / "export"; dst.mkdir(parents=True, exist_ok=True)
    if not (dst / "download.verified").exists():
        run("gcloud", "storage", "rsync", "-r", f"{g['bucket']}/", str(dst) + "/")
        remote = sorted(l.split()[0] + " " + l.split()[2].replace(g["bucket"] + "/", "") for l in run("gcloud", "storage", "ls", "-l", "-r", f"{g['bucket']}/**").splitlines() if "parquet" in l)
        local = sorted(f"{p.stat().st_size} {p.relative_to(dst)}" for p in dst.rglob("*.parquet"))
        if remote != local: raise RuntimeError("download does not match the bucket listing")
        for p in dst.rglob("*.parquet"): p.chmod(0o444)
        (dst / "download.verified").write_text(datetime.datetime.now(datetime.timezone.utc).isoformat())
    done_file = dst / "loaded.txt"; done_file.touch(); done = set(done_file.read_text().split("\n"))
    for p in sorted((dst / "v1").glob("part-*.parquet")):
        rel = str(p.relative_to(paths["archive"]))
        if rel in done: continue
        ch("DROP TABLE IF EXISTS webcat.staging"); ch("CREATE TABLE webcat.staging AS webcat.entries")
        sql = pathlib.Path(__file__).with_name("load_v1.sql").read_text().split("INSERT INTO webcat.entries SELECT")[0].replace("INSERT INTO webcat.stage_v1", "INSERT INTO webcat.staging")
        for attempt in range(20):
            try: subprocess.run(["clickhouse-client", f"--param_file={rel}", "--param_lo=0", "--param_hi=0", "--param_reload=1", "--multiquery"], input=sql, text=True, check=True, capture_output=True); break
            except subprocess.CalledProcessError:
                if attempt == 19: raise
                __import__("time").sleep(30)
        ch("ALTER TABLE webcat.entries ATTACH PARTITION ID 'all' FROM webcat.staging")
        with done_file.open("a") as f: f.write(rel + "\n")
    ch("DROP TABLE IF EXISTS webcat.staging")
    logging.info("rekor-v1 history loaded: %d files", len(done_file.read_text().split()))

if __name__ == "__main__":
    import sys, tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    paths = {k: pathlib.Path(v) for k, v in cfg["paths"].items()}
    if sys.argv[1:2] == ["export"]: export(cfg)
    elif sys.argv[1:2] == ["load-history"]: load_history(cfg, paths)
    else: print("usage: rekor_v1.py export | load-history   (the daily increment runs from monitor.py)")

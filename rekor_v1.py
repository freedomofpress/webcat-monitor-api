"""Rekor v1 daily increment through BigQuery: APPENDS() on the public dataset returns only rows added since the
previous run (~16 GB scanned per day, inside the free tier), exported as ZSTD Parquet, pulled to the archive and
loaded with load_v1.sql. The dataset trails the live log by a few days; the 7-day APPENDS window means this must
run at least weekly, so a gap over 6 days fails loudly instead of silently costing a full scan.
State: <archive>/rekor-v1/daily/state.json {"since": <RFC3339>}; the first "since" is the one-time export's time."""
import datetime, json, logging, os, pathlib, subprocess
from util import ch

PROJECT, DATASET, BUCKET = "webcat-511408", "rekor_export", "gs://webcat-511408-rekor-export"
EXPORT_SQL = pathlib.Path(__file__).with_name("rekor_v1_export.sh").read_text().split("EXPORT_SQL='")[1].split("'\n")[0]
MAX_GAP_DAYS = 6
ENV = {**os.environ, "CLOUDSDK_CONFIG": "/srv/index/gcloud", "HOME": "/srv/index"}

def run(*cmd, **kw):
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True, **kw)
    if r.returncode: raise RuntimeError(f"{cmd[0]} failed: {(r.stderr or r.stdout).strip()[-400:]}")
    return r.stdout

def fetch(src, paths):
    name = src["name"]
    root = paths["archive"] / "rekor-v1" / "daily"; root.mkdir(parents=True, exist_ok=True)
    state_file = root / "state.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {"since": "2026-10-18T10:41:00Z"}  # the one-time export
    since = datetime.datetime.fromisoformat(state["since"].replace("Z", "+00:00"))
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    if (now - since).days > MAX_GAP_DAYS:
        raise RuntimeError(f"{name}: last increment {state['since']} is over {MAX_GAP_DAYS} days old; APPENDS cannot reach back, decide on a re-export")
    tag = now.strftime("%Y%m%dT%H%M%SZ"); table = f"{DATASET}.v1_daily_{tag}"; prefix = f"{BUCKET}/v1_daily/{tag}"
    sql = EXPORT_SQL.replace("`bigquery-public-data.rekor.Entries` e", f"APPENDS(TABLE `bigquery-public-data.rekor.Entries`, TIMESTAMP '{since.isoformat()}', TIMESTAMP '{now.isoformat()}') e") \
                    .replace("`bigquery-public-data.rekor.Identities` i", f"APPENDS(TABLE `bigquery-public-data.rekor.Identities`, TIMESTAMP '{since.isoformat()}', TIMESTAMP '{now.isoformat()}') i")
    run("bq", f"--project_id={PROJECT}", "query", "--use_legacy_sql=false", "--location=US", "--format=none",
        f"--destination_table={table}", "--replace", "--maximum_bytes_billed=200000000000", sql)
    run("bq", f"--project_id={PROJECT}", "extract", "--location=US", "--destination_format=PARQUET", "--compression=ZSTD", table, f"{prefix}/part-*.parquet")
    local = root / tag; local.mkdir(exist_ok=True)
    run("gcloud", "storage", "rsync", "-r", f"{prefix}/", str(local) + "/")
    files = sorted(local.glob("part-*.parquet"))
    for f in files: f.chmod(0o444)
    rows = 0
    for f in files:
        rel = str(f.relative_to(paths["archive"]))
        rows += int(ch(f"SELECT count() FROM file({rel!r}, Parquet)").strip() or 0)
        subprocess.run(["clickhouse-client", f"--param_file={rel}", "--multiquery"], input=pathlib.Path(__file__).with_name("load_v1.sql").read_text(), text=True, check=True, capture_output=True)
    run("gcloud", "storage", "rm", "-r", prefix)
    run("bq", f"--project_id={PROJECT}", "rm", "-f", "-t", table)
    state.update({"since": now.isoformat().replace("+00:00", "Z"), "last_rows": rows, "last_files": len(files)})
    state_file.write_text(json.dumps(state))
    logging.info("%s: +%d rows in %d files for %s .. %s", name, rows, len(files), since.isoformat(), now.isoformat())

"""Rekor v2 (C2SP tlog-tiles): verify every entry bundle against its level-0 hash tile, extract each signer's
certificate into an archive record (every claim-bearing field, same content as the v1 BigQuery export), write
the records as one Parquet file per chunk under <archive>/rekor-v2/<name>/parsed/, load the index rows from
that file with load_v2.sql, keep the hash tiles (32 bytes/entry, enough for the tree check) and drop the bundle.
The index is a projection of the archive: rebuilding it is rerunning load_v2.sql over parsed/*.parquet.
Set keep_bundles = true on a source to also keep the raw bundles zstd-compressed (~540 bytes/entry)."""
import base64, hashlib, json, logging, pathlib, struct, time
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
import zstandard
from cryptography import x509
from util import get, merkle_root, ch

WIDTH = 256
WORKERS = 32
CHUNK = 500    # bundles per archive file + insert; 128k rows keeps ClickHouse under ~1 GB while v1 files load alongside
ZSTD_LEVEL = 9
FULCIO = "1.3.6.1.4.1.57264."
DROP = {"1.3.6.1.4.1.11129.2.4.2", "1.3.6.1.5.5.7.1.1"}  # SCT and authority info access; plus every 2.5.29.* (SAN is read separately)
ARCHIVE_COLUMNS = ("log_index UInt64, time DateTime, kind String, issuer_dn String, not_before DateTime, "
                   "san_uris Array(String), san_emails Array(String), san_other Array(String), key_details String, key_digest String, ext Map(String, String)")
LOAD_SQL = [q for q in pathlib.Path(__file__).with_name("load_v2.sql").read_text().split(";\n") if q.strip() and not q.strip().startswith("--") or "INSERT" in q]

def tile_path(n):
    """tlog-tiles path element: 1234067 -> x001/x234/067, 5 -> 005."""
    s = f"{n:03d}"
    s = "0" * (-len(s) % 3) + s
    parts = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])

def split_bundle(bundle):
    off, out = 0, []
    while off < len(bundle):
        (n,) = struct.unpack(">H", bundle[off:off + 2])
        out.append(bundle[off + 2:off + 2 + n])
        off += 2 + n
    if off != len(bundle): raise ValueError("trailing bytes in bundle")
    return out

def der_text(b):
    """Fulcio OIDs >= 1.8 are DER UTF8String; older ones and custom OIDs may be raw."""
    if b[:1] == b"\x0c" and len(b) >= 2:
        n, i = b[1], 2
        if n >= 0x80: k = n - 0x80; n = int.from_bytes(b[2:2 + k], "big"); i = 2 + k
        return b[i:i + n].decode("utf-8", "replace")
    return b.decode("utf-8", "replace")

def verifiers(entry):
    """Yield (kind, verifier dict) for every signer in a v2 entry body."""
    kind, spec = entry["kind"], entry["spec"]
    if kind == "hashedrekord": yield kind, spec["hashedRekordV002"]["signature"]["verifier"]
    elif kind == "dsse":
        for s in spec["dsseV002"]["signatures"]: yield kind, s["verifier"]
    else: raise ValueError(f"unknown v2 kind {kind}")

def record(index, now, kind, v):
    """Archive record for one signer: everything a claim could match on, nothing per-entry that cannot."""
    r = {"log_index": index, "time": now, "kind": kind, "issuer_dn": "", "not_before": "1970-01-01 00:00:00",
         "san_uris": [], "san_emails": [], "san_other": [], "key_details": v.get("keyDetails", ""), "key_digest": "", "ext": {}}
    if "x509Certificate" in v:
        cert = x509.load_der_x509_certificate(base64.b64decode(v["x509Certificate"]["rawBytes"]))
        r["issuer_dn"] = cert.issuer.rfc4514_string()
        r["not_before"] = cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
        for e in cert.extensions:
            oid = e.oid.dotted_string
            if oid == "2.5.29.17":
                r["san_uris"] = e.value.get_values_for_type(x509.UniformResourceIdentifier)
                r["san_emails"] = e.value.get_values_for_type(x509.RFC822Name)
                r["san_other"] = [der_text(o.value) for o in e.value.get_values_for_type(x509.OtherName)]  # Fulcio username identities (1.3.6.1.4.1.57264.1.7)
            elif oid not in DROP and not oid.startswith("2.5.29."):  # standard X.509 extensions carry no claims
                r["ext"][oid] = der_text(e.value.value if isinstance(e.value, x509.UnrecognizedExtension) else e.value.public_bytes())
    else:
        r["key_digest"] = hashlib.sha256(base64.b64decode(v["publicKey"]["rawBytes"])).hexdigest()
    return r

def fetch(src, paths):
    name, url, keep = src["name"], src["url"].rstrip("/"), src.get("keep_bundles", False)
    root = paths["archive"] / "rekor-v2" / name
    (root / "parsed").mkdir(parents=True, exist_ok=True)
    cp = get(url + "/checkpoint").decode()
    origin, size, root_hash = cp.split("\n")[0], int(cp.split("\n")[1]), base64.b64decode(cp.split("\n")[2])
    full, tail = divmod(size, WIDTH)
    tail_hashes = get(f"{url}/tile/0/{tile_path(full)}.p/{tail}") if tail else b""
    if len(tail_hashes) != 32 * tail: raise RuntimeError(f"{name}: partial tile has {len(tail_hashes) // 32} hashes, want {tail}")

    roots_file = root / "tile_roots.bin"   # 32 bytes per full tile: subtree root, makes the checkpoint check take seconds
    state_file = root / "state.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    parsed = state.get("parsed", 0)         # bundles whose rows are in ClickHouse
    have_roots = roots_file.stat().st_size // 32 if roots_file.exists() else 0
    # A crash between a chunk's inserts and its state write would duplicate that chunk on resume. The state carries a
    # dirty flag across that window; only then is the (expensive, full-table) cleanup delete run.
    if state.get("dirty"):
        for t in ("entries", "claims", "sha"):
            ch(f"DELETE FROM webcat.{t} WHERE log = '{name}' AND log_index >= {parsed * WIDTH}") if t != "claims" else None
        state["dirty"] = False; state_file.write_text(json.dumps(state))
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    def one(n):
        p = tile_path(n)
        bdst, hdst = root / "tile" / "entries" / (p + ".zst"), root / "tile" / "0" / p
        bundle = zstandard.decompress(bdst.read_bytes()) if bdst.exists() else get(f"{url}/tile/entries/{p}")
        hashes = hdst.read_bytes() if hdst.exists() else get(f"{url}/tile/0/{p}")
        if len(hashes) != 32 * WIDTH: raise RuntimeError(f"{name}: hash tile {n} is not full")
        entries = split_bundle(bundle)
        if len(entries) != WIDTH: raise RuntimeError(f"{name}: bundle {n} has {len(entries)} entries")
        rows = []
        for k, e in enumerate(entries):
            if hashlib.sha256(b"\x00" + e).digest() != hashes[32 * k:32 * k + 32]:
                raise RuntimeError(f"{name}: bundle {n} entry {k} does not match its hash tile")
            entry = json.loads(e)
            rows += [record(n * WIDTH + k, now, kind, v) for kind, v in verifiers(entry)]
        hdst.parent.mkdir(parents=True, exist_ok=True)
        if not hdst.exists(): hdst.write_bytes(hashes); hdst.chmod(0o444)
        if keep and not bdst.exists():
            bdst.parent.mkdir(parents=True, exist_ok=True)
            tmp = bdst.with_suffix(".tmp"); tmp.write_bytes(zstandard.compress(bundle, ZSTD_LEVEL)); tmp.rename(bdst)
        elif not keep and bdst.exists(): bdst.unlink()
        return merkle_root([hashes[i:i + 32] for i in range(0, 32 * WIDTH, 32)]), rows

    with ThreadPoolExecutor(WORKERS) as ex, roots_file.open("r+b" if roots_file.exists() else "wb") as rf:
        for start in range(parsed, full, CHUNK):
            end = min(start + CHUNK, full)
            archive = f"rekor-v2/{name}/parsed/{start:09d}.parquet"   # relative to ClickHouse user_files_path = the archive volume
            apath = paths["archive"] / archive
            # Invariant: a read-only archive file is complete and already loaded. It is never rewritten; a resume only
            # re-projects it into the index. A writable one is a leftover from a crash mid-write and is replaced.
            if apath.exists() and not (apath.stat().st_mode & 0o200) and have_roots >= end:
                state["dirty"] = True; state_file.write_text(json.dumps(state))
                for q in LOAD_SQL: ch(q, params={"log": name, "file": archive})
                state.update({"origin": origin, "parsed": end, "dirty": False}); state_file.write_text(json.dumps(state))
                logging.info("%s: %d/%d bundles, archive reused", name, end, full); continue
            results = list(ex.map(one, range(start, end)))
            state["dirty"] = True; state_file.write_text(json.dumps(state))
            body = "\n".join(json.dumps(r) for _, rows in results for r in rows)
            ch(f"INSERT INTO FUNCTION file('{archive}', 'Parquet', '{ARCHIVE_COLUMNS}') "
               "SETTINGS engine_file_truncate_on_insert = 1, output_format_parquet_compression_method = 'zstd' FORMAT JSONEachRow", body.encode())
            for q in LOAD_SQL: ch(q, params={"log": name, "file": archive})
            apath.chmod(0o444)
            state["dirty"] = False
            if end > have_roots:
                rf.seek(32 * max(start, have_roots)); rf.write(b"".join(r for r, _ in results[max(start, have_roots) - start:])); rf.flush()
                have_roots = end
            state.update({"origin": origin, "parsed": end}); state_file.write_text(json.dumps(state))
            logging.info("%s: %d/%d bundles parsed", name, end, full)

    roots = roots_file.read_bytes()
    nodes = [roots[i:i + 32] for i in range(0, 32 * full, 32)]
    if tail: nodes.append(merkle_root([tail_hashes[i:i + 32] for i in range(0, 32 * tail, 32)]))
    if merkle_root(nodes) != root_hash:
        raise RuntimeError(f"{name}: tile roots do not hash to the checkpoint root at size {size}")
    # ponytail: checkpoint signature is not verified (no ed25519 in the stdlib). The signed checkpoint is stored raw.
    (root / "checkpoint").write_text(cp)
    state.update({"size": size, "bundles": full}); state_file.write_text(json.dumps(state))
    logging.info("%s: size %d, %d full bundles, root verified", name, size, full)

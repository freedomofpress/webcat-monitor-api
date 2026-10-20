"""Rekor v2 shards (C2SP tlog-tiles). Each bundle of 256 entries is verified against its level-0 hash tile, every
signer certificate is extracted into an archive record (Parquet, one file per CHUNK bundles), the records are loaded
by load_v2.sql, the hash tiles are kept for the tree check and the bundle is dropped. Tile roots are checked against
the signed checkpoint every run. The index is a projection of the archive."""
import base64, hashlib, json, logging, pathlib, struct, time
from concurrent.futures import ThreadPoolExecutor
from util import get, ch, record_status
from verify import merkle_root, verify_checkpoint

WIDTH, CHUNK, WORKERS, ZSTD_LEVEL = 256, 500, 32, 9
DROP = {"1.3.6.1.4.1.11129.2.4.2", "1.3.6.1.5.5.7.1.1"}  # SCT, AIA; every 2.5.29.* is dropped too, the SAN is read separately
ARCHIVE_COLUMNS = ("log_index UInt64, time DateTime, kind String, issuer_dn String, not_before DateTime, san_uris Array(String), "
                   "san_emails Array(String), san_other Array(String), key_details String, key_digest String, key_raw String, "
                   "artifact_digest String, ext Map(String, String)")
LOAD_SQL = [q for q in pathlib.Path(__file__).with_name("load_v2.sql").read_text().split(";\n") if any(l.strip() and not l.strip().startswith("--") for l in q.split("\n"))]

def tile_path(n):
    """1234067 -> x001/x234/067"""
    s = f"{n:03d}"; s = "0" * (-len(s) % 3) + s
    parts = [s[i:i + 3] for i in range(0, len(s), 3)]
    return "/".join(["x" + p for p in parts[:-1]] + [parts[-1]])

def split_bundle(bundle):
    off, out = 0, []
    while off < len(bundle):
        (n,) = struct.unpack(">H", bundle[off:off + 2])
        out.append(bundle[off + 2:off + 2 + n]); off += 2 + n
    if off != len(bundle): raise ValueError("trailing bytes in bundle")
    return out

def der_text(b):
    """DER UTF8String -> text; anything else as-is (Fulcio OIDs below 1.8 and custom OIDs are raw)."""
    if b[:1] == b"\x0c" and len(b) >= 2:
        n, i = b[1], 2
        if n >= 0x80: k = n - 0x80; n = int.from_bytes(b[2:2 + k], "big"); i = 2 + k
        return b[i:i + n].decode("utf-8", "replace")
    return b.decode("utf-8", "replace")

def verifiers(entry):
    """(kind, verifier, artifact digest hex) per signer of a v2 entry."""
    kind, spec = entry["kind"], entry["spec"]
    if kind == "hashedrekord":
        h = spec["hashedRekordV002"]; yield kind, h["signature"]["verifier"], base64.b64decode(h["data"]["digest"]).hex()
    elif kind == "dsse":
        d = spec["dsseV002"]
        for s in d["signatures"]: yield kind, s["verifier"], base64.b64decode(d["payloadHash"]["digest"]).hex()
    else: raise ValueError(f"unknown v2 kind {kind}")

def record(index, now, kind, v, digest):
    """Archive record for one signer. `time` is the fetch time: a v2 leaf carries none, the index uses not_before."""
    from cryptography import x509
    r = {"log_index": index, "time": now, "kind": kind, "issuer_dn": "", "not_before": "1970-01-01 00:00:00", "san_uris": [],
         "san_emails": [], "san_other": [], "key_details": v.get("keyDetails", ""), "key_digest": "", "key_raw": "", "artifact_digest": digest, "ext": {}}
    if "x509Certificate" in v:
        cert = x509.load_der_x509_certificate(base64.b64decode(v["x509Certificate"]["rawBytes"]))
        r["issuer_dn"], r["not_before"] = cert.issuer.rfc4514_string(), cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S")
        for e in cert.extensions:
            oid = e.oid.dotted_string
            if oid == "2.5.29.17":
                r["san_uris"] = e.value.get_values_for_type(x509.UniformResourceIdentifier)
                r["san_emails"] = e.value.get_values_for_type(x509.RFC822Name)
                r["san_other"] = [der_text(o.value) for o in e.value.get_values_for_type(x509.OtherName)]
            elif oid not in DROP and not oid.startswith("2.5.29."):
                r["ext"][oid] = der_text(e.value.value if isinstance(e.value, x509.UnrecognizedExtension) else e.value.public_bytes())
    elif v.get("publicKey", {}).get("rawBytes"):
        r["key_raw"] = v["publicKey"]["rawBytes"]
        r["key_digest"] = hashlib.sha256(base64.b64decode(r["key_raw"])).hexdigest()
    return r

def process_bundle(name, url, root, n, now, keep, force=False):
    """Bundle n (stored or fetched; force refetches) verified against its hash tile -> (subtree root, archive rows)."""
    import zstandard
    p = tile_path(n)
    bdst, hdst = root / "tile" / "entries" / (p + ".zst"), root / "tile" / "0" / p
    bundle = zstandard.decompress(bdst.read_bytes()) if bdst.exists() and not force else get(f"{url}/tile/entries/{p}")
    hashes = hdst.read_bytes() if hdst.exists() else get(f"{url}/tile/0/{p}")
    if len(hashes) != 32 * WIDTH: raise RuntimeError(f"{name}: hash tile {n} is not full")
    entries = split_bundle(bundle)
    if len(entries) != WIDTH: raise RuntimeError(f"{name}: bundle {n} has {len(entries)} entries")
    rows = []
    for k, e in enumerate(entries):
        if hashlib.sha256(b"\x00" + e).digest() != hashes[32 * k:32 * k + 32]: raise RuntimeError(f"{name}: bundle {n} entry {k} does not match its hash tile")
        rows += [record(n * WIDTH + k, now, kind, v, digest) for kind, v, digest in verifiers(json.loads(e))]
    hdst.parent.mkdir(parents=True, exist_ok=True)
    if not hdst.exists(): hdst.write_bytes(hashes); hdst.chmod(0o444)
    if keep and not bdst.exists():
        bdst.parent.mkdir(parents=True, exist_ok=True)
        tmp = bdst.with_suffix(".tmp"); tmp.write_bytes(zstandard.compress(bundle, ZSTD_LEVEL)); tmp.rename(bdst)
    elif not keep and bdst.exists(): bdst.unlink()
    return merkle_root([hashes[i:i + 32] for i in range(0, 32 * WIDTH, 32)]), rows

def write_archive(archive, rows):
    ch(f"INSERT INTO FUNCTION file('{archive}', 'Parquet', '{ARCHIVE_COLUMNS}') SETTINGS engine_file_truncate_on_insert = 1, "
       "output_format_parquet_compression_method = 'zstd' FORMAT JSONEachRow", "\n".join(json.dumps(r) for r in rows).encode())

def rewrite_archive(src, paths, until):
    """Refetch bundles [0, until) and rewrite their archive chunks (record schema change); then build.py reproject."""
    name, url = src["name"], src["url"].rstrip("/")
    root = paths["archive"] / "rekor-v2" / name
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    done_file = root / "rewrite.done"; done = set(done_file.read_text().split()) if done_file.exists() else set()
    with ThreadPoolExecutor(WORKERS) as ex:
        for start in range(0, until, CHUNK):
            if str(start) in done: continue
            results = list(ex.map(lambda n: process_bundle(name, url, root, n, now, False, force=True), range(start, min(start + CHUNK, until))))
            archive = f"rekor-v2/{name}/parsed/{start:09d}.parquet"; apath = paths["archive"] / archive
            if apath.exists(): apath.chmod(0o644)
            write_archive(archive, [r for _, rows in results for r in rows]); apath.chmod(0o444)
            with done_file.open("a") as f: f.write(f"{start}\n")
            logging.info("%s: rewrote archive chunk %d", name, start)

def fetch(src, paths):
    name, url, keep = src["name"], src["url"].rstrip("/"), src.get("keep_bundles", False)
    root = paths["archive"] / "rekor-v2" / name
    (root / "parsed").mkdir(parents=True, exist_ok=True)
    cp = get(url + "/checkpoint").decode()
    origin, size, root_hash = cp.split("\n")[0], int(cp.split("\n")[1]), base64.b64decode(cp.split("\n")[2])
    cosigs = verify_checkpoint(cp, src.get("origin", url.split("://")[1]), base64.b64decode(src["key"]))
    full, tail = divmod(size, WIDTH)
    tail_hashes = get(f"{url}/tile/0/{tile_path(full)}.p/{tail}") if tail else b""
    if len(tail_hashes) != 32 * tail: raise RuntimeError(f"{name}: partial tile has {len(tail_hashes) // 32} hashes, want {tail}")

    roots_file, state_file = root / "tile_roots.bin", root / "state.json"   # roots: 32 bytes per full tile
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    parsed = state.get("parsed", 0)
    have_roots = roots_file.stat().st_size // 32 if roots_file.exists() else 0
    if state.get("dirty"):  # crashed between a chunk's inserts and its state write: drop what that chunk may have inserted
        for t in ("entries", "entries_by_index", "entries_by_time"): ch(f"DELETE FROM webcat.{t} WHERE log = '{name}' AND log_index >= {parsed * WIDTH}")
        state["dirty"] = False; state_file.write_text(json.dumps(state))
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    save = lambda **kw: (state.update(kw), state_file.write_text(json.dumps(state)))

    with ThreadPoolExecutor(WORKERS) as ex, roots_file.open("r+b" if roots_file.exists() else "wb") as rf:
        for start in range(parsed, full, CHUNK):
            end = min(start + CHUNK, full)
            archive = f"rekor-v2/{name}/parsed/{start:09d}.parquet"; apath = paths["archive"] / archive
            if apath.exists() and not (apath.stat().st_mode & 0o200) and have_roots >= end:  # read-only = complete: reuse
                save(dirty=True)
                for q in LOAD_SQL: ch(q, params={"log": name, "file": archive})
                save(origin=origin, parsed=end, dirty=False); logging.info("%s: %d/%d bundles, archive reused", name, end, full); continue
            results = list(ex.map(lambda n: process_bundle(name, url, root, n, now, keep), range(start, end)))
            save(dirty=True)
            write_archive(archive, [r for _, rows in results for r in rows])
            for q in LOAD_SQL: ch(q, params={"log": name, "file": archive})
            apath.chmod(0o444)
            if end > have_roots:
                rf.seek(32 * max(start, have_roots)); rf.write(b"".join(r for r, _ in results[max(start, have_roots) - start:])); rf.flush(); have_roots = end
            save(origin=origin, parsed=end, dirty=False)
            logging.info("%s: %d/%d bundles parsed", name, end, full)

    roots = roots_file.read_bytes()
    nodes = [roots[i:i + 32] for i in range(0, 32 * full, 32)]
    if tail: nodes.append(merkle_root([tail_hashes[i:i + 32] for i in range(0, 32 * tail, 32)]))
    if merkle_root(nodes) != root_hash: raise RuntimeError(f"{name}: tile roots do not hash to the checkpoint root at size {size}")
    (root / "checkpoint").write_text(cp); save(size=size, bundles=full)
    record_status(name, {"size": size, "root": root_hash.hex(), "entries_hash_to_tiles": True, "tiles_hash_to_root": True, "log_signature": True, "cosignatures_verified": cosigs})
    logging.info("%s: size %d, %d full bundles, root verified, checkpoint signature OK", name, size, full)

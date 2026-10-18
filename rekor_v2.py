"""Rekor v2 (C2SP tlog-tiles): verify every entry bundle against its level-0 hash tile, parse each entry's
certificate into one webcat.entries row, keep the hash tiles (32 bytes/entry, enough for the tree check),
and drop the bundle. Tile roots are checked against the checkpoint root at the end of each run.
Set keep_bundles = true on the source to also store bundles zstd-compressed (~540 bytes/entry)."""
import base64, hashlib, json, logging, struct, time
from concurrent.futures import ThreadPoolExecutor
import zstandard
from cryptography import x509
from util import get, merkle_root, ch

WIDTH = 256
WORKERS = 32
CHUNK = 2000   # bundles per insert + progress checkpoint
ZSTD_LEVEL = 9
FULCIO = "1.3.6.1.4.1.57264."
ISSUER_OIDS = (FULCIO + "1.8", FULCIO + "1.1")
NOISE = {FULCIO + s for s in ("1.1", "1.8", "1.3", "1.10", "1.13", "1.19", "1.15", "1.17", "1.21")}  # same set as load_v1.sql

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

def row(log, index, now, kind, v):
    if "x509Certificate" in v:
        cert = x509.load_der_x509_certificate(base64.b64decode(v["x509Certificate"]["rawBytes"]))
        ext, identity = {}, ""
        for e in cert.extensions:
            oid = e.oid.dotted_string
            if oid == "2.5.29.17":
                uris = e.value.get_values_for_type(x509.UniformResourceIdentifier)
                mails = e.value.get_values_for_type(x509.RFC822Name)
                identity = uris[0] if uris else mails[0] if mails else ""
            elif oid.startswith(FULCIO) or isinstance(e.value, x509.UnrecognizedExtension):
                ext[oid] = der_text(e.value.value)
        issuer = next((ext[o] for o in ISSUER_OIDS if o in ext), None) or cert.issuer.rfc4514_string()
        ext = {k: s for k, s in ext.items() if k not in NOISE}
    else:
        key = base64.b64decode(v["publicKey"]["rawBytes"])
        issuer, identity, ext = v.get("keyDetails", "key"), hashlib.sha256(key).hexdigest(), {}
    return {"log": log, "log_index": index, "time": now, "kind": kind, "issuer": issuer, "identity": identity, "ext": ext}

def fetch(src, paths):
    name, url, keep = src["name"], src["url"].rstrip("/"), src.get("keep_bundles", False)
    root = paths["archive"] / "rekor-v2" / name
    root.mkdir(parents=True, exist_ok=True)
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
    # Rows from a chunk that was inserted but not recorded (crash in between) would be duplicated: clear them first.
    ch(f"ALTER TABLE webcat.entries DELETE WHERE log = '{name}' AND log_index >= {parsed * WIDTH}")
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
            rows += [row(name, n * WIDTH + k, now, kind, v) for kind, v in verifiers(entry)]
        hdst.parent.mkdir(parents=True, exist_ok=True)
        if not hdst.exists(): hdst.write_bytes(hashes)
        if keep and not bdst.exists():
            bdst.parent.mkdir(parents=True, exist_ok=True)
            tmp = bdst.with_suffix(".tmp"); tmp.write_bytes(zstandard.compress(bundle, ZSTD_LEVEL)); tmp.rename(bdst)
        elif not keep and bdst.exists(): bdst.unlink()
        return merkle_root([hashes[i:i + 32] for i in range(0, 32 * WIDTH, 32)]), rows

    with ThreadPoolExecutor(WORKERS) as ex, roots_file.open("r+b" if roots_file.exists() else "wb") as rf:
        for start in range(parsed, full, CHUNK):
            end = min(start + CHUNK, full)
            results = list(ex.map(one, range(start, end)))
            body = "\n".join(json.dumps(r) for _, rows in results for r in rows)
            ch("INSERT INTO webcat.entries FORMAT JSONEachRow", body.encode())
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

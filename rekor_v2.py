"""Rekor v2 (C2SP tlog-tiles): mirror the log as files so the archive is itself a servable copy.
Entry bundles are stored zstd-compressed (7x smaller). Each bundle is checked against its level-0 hash tile
before it is kept, and the tile roots are checked against the checkpoint root at the end of each run."""
import base64, hashlib, json, logging, struct
import zstandard  # Debian: python3-zstandard. Python 3.14+ could use compression.zstd instead.
from concurrent.futures import ThreadPoolExecutor
from util import get, merkle_root

WIDTH = 256
ZSTD_LEVEL = 9  # measured: -9 is 8% under gzip -6, higher levels gain nothing on base64 certs
WORKERS = 16
CHUNK = 2000  # bundles per progress checkpoint

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

def fetch(src, paths):
    name, url = src["name"], src["url"].rstrip("/")
    root = paths["archive"] / "rekor-v2" / name
    root.mkdir(parents=True, exist_ok=True)
    cp = get(url + "/checkpoint").decode()
    origin, size, root_hash = cp.split("\n")[0], int(cp.split("\n")[1]), base64.b64decode(cp.split("\n")[2])
    full, tail = divmod(size, WIDTH)
    # Fetch the partial tail tile first: it only exists for the exact current size.
    tail_hashes = get(f"{url}/tile/0/{tile_path(full)}.p/{tail}") if tail else b""
    if len(tail_hashes) != 32 * tail: raise RuntimeError(f"{name}: partial tile has {len(tail_hashes) // 32} hashes, want {tail}")

    roots_file = root / "tile_roots.bin"  # 32 bytes per full tile: subtree root, lets the checkpoint check run in seconds
    have = roots_file.stat().st_size // 32 if roots_file.exists() else 0

    def one(n):
        p = tile_path(n)
        dst, hdst = root / "tile" / "entries" / (p + ".zst"), root / "tile" / "0" / p
        if dst.exists() and hdst.exists():
            return merkle_root([hdst.read_bytes()[i:i + 32] for i in range(0, 32 * WIDTH, 32)])
        bundle, hashes = get(f"{url}/tile/entries/{p}"), get(f"{url}/tile/0/{p}")
        if len(hashes) != 32 * WIDTH: raise RuntimeError(f"{name}: hash tile {n} is not full")
        entries = split_bundle(bundle)
        if len(entries) != WIDTH: raise RuntimeError(f"{name}: bundle {n} has {len(entries)} entries")
        for k, e in enumerate(entries):
            if hashlib.sha256(b"\x00" + e).digest() != hashes[32 * k:32 * k + 32]:
                raise RuntimeError(f"{name}: bundle {n} entry {k} does not match its hash tile")
        for d in (dst, hdst): d.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_suffix(".tmp"); tmp.write_bytes(zstandard.compress(bundle, ZSTD_LEVEL))  # a ZstdCompressor instance is not thread safe; this makes one per call; tmp.rename(dst)
        hdst.write_bytes(hashes)
        return merkle_root([hashes[i:i + 32] for i in range(0, 32 * WIDTH, 32)])

    with ThreadPoolExecutor(WORKERS) as ex, roots_file.open("ab") as rf:
        for start in range(have, full, CHUNK):
            for r in ex.map(one, range(start, min(start + CHUNK, full))): rf.write(r)
            rf.flush()
            logging.info("%s: %d/%d bundles", name, min(start + CHUNK, full), full)

    roots = roots_file.read_bytes()
    nodes = [roots[i:i + 32] for i in range(0, 32 * full, 32)]
    if tail: nodes.append(merkle_root([tail_hashes[i:i + 32] for i in range(0, 32 * tail, 32)]))
    if merkle_root(nodes) != root_hash:
        raise RuntimeError(f"{name}: tile roots do not hash to the checkpoint root at size {size}")
    # ponytail: checkpoint signature is not verified (no ed25519 in the stdlib). The signed checkpoint is stored raw.
    (root / "checkpoint").write_text(cp)
    (root / "state.json").write_text(json.dumps({"origin": origin, "size": size, "bundles": full}))
    logging.info("%s: size %d, %d full bundles (+%d), root verified", name, size, full, full - have)

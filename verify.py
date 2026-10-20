"""Verification: Merkle trees (RFC 6962 / RFC 9162), signed notes and checkpoints (C2SP), Sigsum tree heads,
Rekor v1 signed tree heads, and the Rekor v1 leaf-list check. Keys are pinned in sources.toml; a signature that
does not verify is an error, never a warning. python3-cryptography is imported lazily so the Merkle half and the
offline tests need only the stdlib."""
import base64, hashlib, json, logging, pathlib, struct, urllib.parse, urllib.request
from util import get, record_status

# --- Merkle -----------------------------------------------------------------------------------------------------

def node(left, right): return hashlib.sha256(b"\x01" + left + right).digest()

class Frontier:
    """Streaming compact range: the roots of the perfect subtrees covering [0, size), largest first."""
    def __init__(self, size=0, hashes=()):
        self.size, self.hashes = size, list(hashes)
    def append(self, leaf_hash):
        h, n = leaf_hash, self.size
        self.size += 1
        while n & 1:
            h = node(self.hashes.pop(), h); n >>= 1
        self.hashes.append(h)
    def root(self):
        if not self.hashes: return hashlib.sha256(b"").digest()
        h = self.hashes[-1]
        for left in reversed(self.hashes[:-1]): h = node(left, h)
        return h
    def state(self): return {"size": self.size, "hashes": [x.hex() for x in self.hashes]}
    @classmethod
    def load(cls, s): return cls(s["size"], [bytes.fromhex(x) for x in s["hashes"]])

def merkle_root(hashes):
    f = Frontier()
    for h in hashes: f.append(h)
    return f.root()

def verify_consistency(first, second, root1, root2, proof):
    """RFC 9162 section 2.1.4.2: is the tree of size `second` an extension of the tree of size `first`?"""
    if first == second: return root1 == root2 and not proof
    if first == 0: return not proof
    if not proof: return False
    fn, sn = first - 1, second - 1
    while fn & 1: fn >>= 1; sn >>= 1
    proof = list(proof)
    if fn: fr = sr = proof.pop(0)
    else: fr = sr = root1
    for c in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node(c, fr); sr = node(c, sr)
            while not fn & 1 and fn: fn >>= 1; sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and fr == root1 and sr == root2

# --- Signed notes (C2SP signed-note, tlog-checkpoint, tlog-cosignature) -----------------------------------------

def note_key_id(name, pubkey_raw, alg=0x01):
    """4-byte note key id: SHA-256(name || '\\n' || alg || pubkey)[:4]; alg 0x01 Ed25519, 0x04 cosignature/v1."""
    return hashlib.sha256(name.encode() + b"\n" + bytes([alg]) + pubkey_raw).digest()[:4]

def split_note(text):
    body, _, sigs = text.partition("\n\n")
    out = []
    for line in sigs.splitlines():
        if line.startswith("— "):
            _, name, b64 = line.split(" ", 2)
            out.append((name, base64.b64decode(b64)))
    return body + "\n", out

def verify_checkpoint(text, origin, log_key_raw, cosigners=None):
    """Verify the log's Ed25519 signature on a tlog checkpoint; count valid cosignature/v1 lines from `cosigners`
    ({name: pubkey_raw}). Raises on a missing or bad log signature or a bad cosignature from a known witness."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    body, sigs = split_note(text)
    if not body.startswith(origin + "\n"): raise ValueError(f"checkpoint origin is not {origin}")
    log_sigs = [s for n, s in sigs if n == origin and s[:4] == note_key_id(origin, log_key_raw)]
    if not log_sigs: raise ValueError(f"no signature by the pinned key for {origin}")
    ed25519.Ed25519PublicKey.from_public_bytes(log_key_raw).verify(log_sigs[0][4:], body.encode())
    ok = 0
    for name, sig in sigs:
        pub = (cosigners or {}).get(name)
        if not pub or name == origin or sig[:4] != note_key_id(name, pub, 0x04) or len(sig) != 76: continue
        t = struct.unpack(">Q", sig[4:12])[0]
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig[12:], f"cosignature/v1\ntime {t}\n".encode() + body.encode()); ok += 1
    return ok

def verify_rekor_v1_sth(note_text, pem):
    """Rekor v1 signed tree head: note 'rekor.sigstore.dev - <treeID>\\n<size>\\n<root b64>\\n', key-id-prefixed
    ECDSA P-256/SHA-256 DER signature. Returns (tree_id, size, root bytes)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    body, sigs = split_note(note_text)
    if not sigs: raise ValueError("unsigned tree head")
    serialization.load_pem_public_key(pem.encode()).verify(sigs[0][1][4:], body.encode(), ec.ECDSA(hashes.SHA256()))
    origin, size, root = body.split("\n")[:3]
    return origin.split(" - ")[1], int(size), base64.b64decode(root)

def verify_sigsum_tree_head(text, log_key_hex, witnesses=None):
    """Sigsum get-tree-head text. Log signature: Ed25519 over 'sigsum.org/v1/tree/<log key hash>\\n<size>\\n<root b64>\\n'.
    Cosignatures: Ed25519 over 'cosignature/v1\\ntime <t>\\n' + that text; `witnesses` maps key hash hex to key hex.
    Returns (size, root bytes, valid cosignature count); raises on a bad log signature or a bad known cosignature."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    kv, cosigs = {}, []
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if k == "cosignature": cosigs.append(v.split())
        else: kv[k] = v
    size, root, log_key = int(kv["size"]), bytes.fromhex(kv["root_hash"]), bytes.fromhex(log_key_hex)
    checkpoint = f"sigsum.org/v1/tree/{hashlib.sha256(log_key).hexdigest()}\n{size}\n{base64.b64encode(root).decode()}\n"
    ed25519.Ed25519PublicKey.from_public_bytes(log_key).verify(bytes.fromhex(kv["signature"]), checkpoint.encode())
    ok = 0
    for key_hash, t, sig in cosigs:
        pub = (witnesses or {}).get(key_hash)
        if not pub: continue
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), f"cosignature/v1\ntime {t}\n{checkpoint}".encode()); ok += 1
    return size, root, ok

# --- Rekor v1 leaf list -----------------------------------------------------------------------------------------
# The dataset has no leaf bodies, but every UUID is tree id || leaf hash. Per shard, a persisted Merkle frontier
# over the leaf hashes in log-index order: frozen shards must reproduce their final root, our prefix of the active
# shard must be consistent with the live signed head (consistency proof from the API). A gap stops the check at the
# last good index and is recorded for the repair.

FRONTIER = pathlib.Path("/srv/index/v1_frontier.json")
MISSING = pathlib.Path("/srv/index/v1_missing.json")

def leaf_stream(from_index):
    """(log_index, tree id bytes, leaf hash) in order from webcat.leaves_v1; fixed-width RowBinary, duplicates collapsed."""
    q = urllib.parse.urlencode({"query": f"SELECT log_index, toFixedString(unhex(tree_id), 8) AS t, leaf_hash FROM webcat.leaves_v1 "
                                          f"WHERE log_index >= {from_index} ORDER BY log_index FORMAT RowBinary "
                                          f"SETTINGS max_threads = 2, max_memory_usage = 1500000000, optimize_read_in_order = 1"})
    with urllib.request.urlopen("http://127.0.0.1:8123/?" + q, timeout=None) as r:
        buf, last = b"", None
        while True:
            chunk = r.read(1 << 20)
            if not chunk: break
            buf += chunk; n = len(buf) // 48
            for idx, tid, h in struct.iter_unpack("<Q8s32s", buf[:n * 48]):
                if last and last[0] == idx:
                    if last[2] != h: raise RuntimeError(f"two different leaf hashes for log index {idx}")
                    continue
                last = (idx, tid, h); yield last
            buf = buf[n * 48:]

def rekor_v1_leaves(src):
    url = src["url"].rstrip("/")
    state = json.loads(FRONTIER.read_text()) if FRONTIER.exists() else {"next_index": 0, "order": [], "shards": {}}
    shards = {k: Frontier.load(v) for k, v in state["shards"].items()}
    order, n = state["order"], state["next_index"]
    gap = {}
    for idx, tid, h in leaf_stream(n):
        if idx != n:
            logging.error("rekor-v1: gap in the leaf list: expected %d, found %d; verified up to %d", n, idx, n - 1)
            MISSING.write_text(json.dumps(list(range(n, min(idx, n + 100000)))))
            gap = {"gap_at": n, "gap_to": idx}
            break
        t = tid.hex()
        if t not in shards: shards[t] = Frontier(); order.append(t)
        elif t != order[-1]: raise RuntimeError(f"rekor-v1: index {idx} in shard {t} after shard {order[-1]} ended")
        shards[t].append(h); n += 1
        if n % 100_000_000 == 0: logging.info("rekor-v1: hashed up to index %d", n)
    FRONTIER.write_text(json.dumps({"next_index": n, "order": order, "shards": {k: v.state() for k, v in shards.items()}, **gap}))
    info = json.loads(get(url + "/api/v1/log").decode())
    heads = {}
    for sth in [info["signedTreeHead"]] + [s["signedTreeHead"] for s in info["inactiveShards"]]:
        tid, size, root = verify_rekor_v1_sth(sth, src["key_pem"]); heads[int(tid)] = (size, root)
    result = {"leaves_hashed": n, "log_signatures": True, "shards": {}, **gap}
    for t in order:
        f, tid = shards[t], int(t, 16); size, root = heads[tid]
        if f.size == size:
            ok, how = f.root() == root, "root matches the signed tree head"
        elif f.size < size:
            p = json.loads(get(f"{url}/api/v1/log/proof?firstSize={f.size}&lastSize={size}&treeID={tid}").decode())
            ok = verify_consistency(f.size, size, f.root(), root, [bytes.fromhex(x) for x in p["hashes"]]) and bytes.fromhex(p["rootHash"]) == root
            how = f"prefix of {f.size} consistent with the signed tree head at {size}"
        else:
            ok, how = False, f"we hold {f.size} leaves but the log reports {size}"
        result["shards"][str(tid)] = {"leaves": f.size, "log_size": size, "verified": ok, "how": how}
        logging.log(logging.INFO if ok else logging.ERROR, "rekor-v1 shard %d: %s: %s", tid, "OK" if ok else "FAILED", how)
    record_status("rekor-v1", result)
    if not all(s["verified"] for s in result["shards"].values()): raise RuntimeError("rekor-v1: leaf list does not verify")

if __name__ == "__main__":
    import tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    rekor_v1_leaves(next(s for s in cfg["source"] if s["type"] == "rekor-v1"))

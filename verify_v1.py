"""Rekor v1 leaf-list verification. The dataset has no leaf bodies, but every UUID is tree id || leaf hash, so the
leaf list itself is checked: per shard, a streaming Merkle frontier over the leaf hashes in log-index order; inactive
shards must reproduce their final root, the active shard our prefix root must be consistent with the live signed
tree head (consistency proof from the API); every tree head signature is verified. The frontiers persist in
/srv/index/v1_frontier.json so a daily run only hashes the new leaves. Gaps or conflicting hashes stop the check
at the last good index and are reported, never papered over."""
import json, logging, pathlib, struct, urllib.parse, urllib.request
from merkle import Frontier, verify_consistency
from notes import verify_rekor_v1_sth
from util import get, record_status

STATE = pathlib.Path("/srv/index/v1_frontier.json")

def stream(from_index):
    """(log_index, tree_id hex, leaf_hash) in order from webcat.leaves_v1, binary, duplicates collapsed."""
    q = urllib.parse.urlencode({"query": f"SELECT log_index, unhex(tree_id) AS t, leaf_hash FROM webcat.leaves_v1 WHERE log_index >= {from_index} ORDER BY log_index FORMAT RowBinary SETTINGS max_threads = 2, max_memory_usage = 1500000000, optimize_read_in_order = 1"})
    with urllib.request.urlopen("http://127.0.0.1:8123/?" + q, timeout=None) as r:
        buf = b""; last = None
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

def run(src):
    url = src["url"].rstrip("/")
    state = json.loads(STATE.read_text()) if STATE.exists() else {"next_index": 0, "shards": {}}
    shards = {k: Frontier.load(v) for k, v in state["shards"].items()}
    order = state.get("order", [])
    n, start = state["next_index"], state["next_index"]
    for idx, tid, h in stream(start):
        if idx != n:
            logging.error("rekor-v1: gap in leaf list at index %d (next expected %d); verified up to %d", idx, n, n - 1); break
        t = tid.hex()
        if t not in shards: shards[t] = Frontier(); order.append(t)
        elif t != order[-1]: raise RuntimeError(f"rekor-v1: index {idx} belongs to shard {t} after shard {order[-1]} already ended")
        shards[t].append(h); n += 1
        if n % 50_000_000 == 0: logging.info("rekor-v1: hashed up to index %d", n)
    state = {"next_index": n, "order": order, "shards": {k: v.state() for k, v in shards.items()}}
    STATE.write_text(json.dumps(state))
    # compare with the log
    info = json.loads(get(url + "/api/v1/log").decode())
    heads = {}
    for sth in [info["signedTreeHead"]] + [s["signedTreeHead"] for s in info["inactiveShards"]]:
        tid, size, root = verify_rekor_v1_sth(sth, src["key_pem"]); heads[int(tid)] = (size, root)
    result = {"leaves_hashed": n, "log_signatures": True, "shards": {}}
    for t in order:
        f = shards[t]; tid = int(t, 16); size, root = heads[tid]
        if f.size == size:
            ok = f.root() == root; how = "root matches the signed tree head"
        elif f.size < size:
            p = json.loads(get(f"{url}/api/v1/log/proof?firstSize={f.size}&lastSize={size}&treeID={tid}").decode())
            ok = verify_consistency(f.size, size, f.root(), root, [bytes.fromhex(x) for x in p["hashes"]]) and bytes.fromhex(p["rootHash"]) == root
            how = f"prefix of {f.size} consistent with the signed tree head at {size}"
        else:
            ok, how = False, f"we hold {f.size} leaves but the log reports {size}"
        result["shards"][str(tid)] = {"leaves": f.size, "log_size": size, "verified": ok, "how": how}
        logging.log(logging.INFO if ok else logging.ERROR, "rekor-v1 shard %d: %s: %s", tid, "OK" if ok else "FAILED", how)
    record_status("rekor-v1", result)
    if not all(s["verified"] for s in result["shards"].values()): raise RuntimeError("rekor-v1: leaf list does not verify against the signed tree heads")

if __name__ == "__main__":
    import sys, tomllib
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg = tomllib.loads(pathlib.Path(__file__).with_name("sources.toml").read_text())
    run(next(s for s in cfg["source"] if s["type"] == "rekor-v1"))

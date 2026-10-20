"""RFC 6962 / RFC 9162 Merkle tree helpers: a streaming compact range (append leaves, read the root at any size,
persist the frontier) and consistency proof verification. Leaf hashes are given, not computed here."""
import hashlib

def node(left, right): return hashlib.sha256(b"\x01" + left + right).digest()

class Frontier:
    """Subtree roots of the perfect binary subtrees covering [0, size), largest first; the standard compact range."""
    def __init__(self, size=0, hashes=()):
        self.size, self.hashes = size, list(hashes)
    def append(self, leaf_hash):
        h, n = leaf_hash, self.size
        self.size += 1
        # merge while the trailing bit pattern says the last subtree has the same size as the new one
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

def verify_consistency(first, second, root1, root2, proof):
    """RFC 9162 section 2.1.4.2. first < second are tree sizes, proof the list of node hashes from the log."""
    if first == second: return root1 == root2 and not proof
    if first == 0: return not proof  # nothing to check; root2 is unconstrained by an empty tree
    if not proof: return False
    fn, sn = first - 1, second - 1
    while fn & 1: fn >>= 1; sn >>= 1
    proof = list(proof)
    fr = sr = proof.pop(0) if fn else root1  # when first is a power of two, root1 is the first node
    if not fn: proof.insert(0, root1); fr = sr = proof.pop(0)
    for c in proof:
        if sn == 0: return False
        if fn & 1 or fn == sn:
            fr = node(c, fr); sr = node(c, sr)
            while not fn & 1 and fn: fn >>= 1; sn >>= 1
        else:
            sr = node(sr, c)
        fn >>= 1; sn >>= 1
    return sn == 0 and fr == root1 and sr == root2

def merkle_root(hashes):
    f = Frontier()
    for h in hashes: f.append(h)
    return f.root()

if __name__ == "__main__":
    import os
    leaves = [hashlib.sha256(bytes([i % 251, i // 251])).digest() for i in range(1000)]
    # reference recursive MTH
    def mth(hs):
        if len(hs) == 1: return hs[0]
        k = 1
        while k * 2 < len(hs): k *= 2
        return node(mth(hs[:k]), mth(hs[k:]))
    for n in (1, 2, 3, 7, 8, 9, 255, 256, 257, 1000):
        assert merkle_root(leaves[:n]) == mth(leaves[:n]), n
    f = Frontier()
    for h in leaves[:300]: f.append(h)
    g = Frontier.load(f.state())
    for h in leaves[300:]: g.append(h)
    assert g.root() == mth(leaves)
    # consistency proofs from a reference implementation of RFC 9162 2.1.4.1
    def subproof(m, hs, b):
        n = len(hs)
        if m == n: return [] if b else [mth(hs)]
        k = 1
        while k * 2 < n: k *= 2
        if m <= k: return subproof(m, hs[:k], b) + [mth(hs[k:])]
        return subproof(m - k, hs[k:], False) + [mth(hs[:k])]
    for a, b in ((1, 2), (3, 7), (7, 8), (8, 9), (6, 8), (255, 256), (256, 1000), (300, 1000), (999, 1000)):
        p = subproof(a, leaves[:b], True)
        assert verify_consistency(a, b, mth(leaves[:a]), mth(leaves[:b]), p), (a, b)
        assert not verify_consistency(a, b, mth(leaves[:a]), os.urandom(32), p), (a, b)
    print("merkle ok")

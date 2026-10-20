"""Offline checks for the parts that would silently corrupt the archive or the verification if wrong.
Run: python3 test.py   (stdlib only; the signature code paths need python3-cryptography and run on the box)"""
import hashlib, os, struct
from rekor_v2 import tile_path, split_bundle, der_text
from sigsum import leaf_hash
from verify import Frontier, merkle_root, node, verify_consistency, note_key_id, split_note

# tlog-tiles paths and bundle framing
assert tile_path(0) == "000" and tile_path(999) == "999" and tile_path(1000) == "x001/000" and tile_path(1234067) == "x001/x234/067"
entries = [b"a", b"bb" * 100, b""]
assert split_bundle(b"".join(struct.pack(">H", len(e)) + e for e in entries)) == entries

# Merkle: frontier == reference MTH at every shape, persisted state resumes, tile roots compose
def mth(hs):
    if len(hs) == 1: return hs[0]
    k = 1
    while k * 2 < len(hs): k *= 2
    return node(mth(hs[:k]), mth(hs[k:]))
leaves = [hashlib.sha256(bytes([i % 251, i // 251])).digest() for i in range(1000)]
for n in (1, 2, 3, 7, 8, 9, 255, 256, 257, 1000): assert merkle_root(leaves[:n]) == mth(leaves[:n]), n
f = Frontier()
for h in leaves[:300]: f.append(h)
g = Frontier.load(f.state())
for h in leaves[300:]: g.append(h)
assert g.root() == mth(leaves)
tiles = [leaves[i:i + 256] for i in range(0, len(leaves), 256)]
assert merkle_root([merkle_root(t) for t in tiles]) == merkle_root(leaves)

# consistency proofs against a reference RFC 9162 2.1.4.1 generator, and a wrong root is rejected
def subproof(m, hs, b):
    n = len(hs)
    if m == n: return [] if b else [mth(hs)]
    k = 1
    while k * 2 < n: k *= 2
    return subproof(m, hs[:k], b) + [mth(hs[k:])] if m <= k else subproof(m - k, hs[k:], False) + [mth(hs[:k])]
for a, b in ((1, 2), (3, 7), (7, 8), (8, 9), (6, 8), (255, 256), (256, 1000), (300, 1000), (999, 1000)):
    p = subproof(a, leaves[:b], True)
    assert verify_consistency(a, b, mth(leaves[:a]), mth(leaves[:b]), p), (a, b)
    assert not verify_consistency(a, b, mth(leaves[:a]), os.urandom(32), p), (a, b)

# Sigsum leaf hash (verified against barreleye's root on 2026-10-18), Fulcio DER text, note parsing
assert leaf_hash(b"c" * 32, b"s" * 64, b"k" * 32) == hashlib.sha256(b"\x00" + b"c" * 32 + b"s" * 64 + b"k" * 32).digest()
assert der_text(b"\x0c\x03abc") == "abc" and der_text(b"\x0c\x81\x80" + b"x" * 128) == "x" * 128 and der_text(b"push") == "push"
body, sigs = split_note("origin\n5\nAAAA\n\n— origin AQIDBAU=\n")
assert body == "origin\n5\nAAAA\n" and sigs == [("origin", b"\x01\x02\x03\x04\x05")]
assert note_key_id("x", b"k") == hashlib.sha256(b"x\n\x01k").digest()[:4]
print("ok")

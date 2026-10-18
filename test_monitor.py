"""Offline checks for the parts that would silently corrupt the archive if wrong. Run: python3 test_monitor.py"""
import hashlib, struct
from rekor_v2 import tile_path, split_bundle, der_text
from sigsum import leaf_hash
from util import merkle_root

assert tile_path(0) == "000" and tile_path(999) == "999" and tile_path(1000) == "x001/000" and tile_path(1234067) == "x001/x234/067"
entries = [b"a", b"bb" * 100, b""]
bundle = b"".join(struct.pack(">H", len(e)) + e for e in entries)
assert split_bundle(bundle) == entries
# merkle over 256-aligned subtree roots equals merkle over the leaves (the property rekor_v2 relies on)
leaves = [hashlib.sha256(bytes([i % 251])).digest() for i in range(256 * 3 + 17)]
tiles = [leaves[i:i + 256] for i in range(0, len(leaves), 256)]
assert merkle_root([merkle_root(t) for t in tiles]) == merkle_root(leaves)
# sigsum leaf hash is H(0x00 || checksum || signature || key_hash); verified against barreleye's root on 2026-10-18
assert leaf_hash(b"c" * 32, b"s" * 64, b"k" * 32) == hashlib.sha256(b"\x00" + b"c" * 32 + b"s" * 64 + b"k" * 32).digest()
# DER UTF8String short and long form, and raw passthrough
assert der_text(b"\x0c\x03abc") == "abc" and der_text(b"\x0c\x81\x80" + b"x" * 128) == "x" * 128 and der_text(b"push") == "push"
print("ok")

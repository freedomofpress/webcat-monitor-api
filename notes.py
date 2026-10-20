"""Signed note / checkpoint verification (C2SP signed-note, tlog-checkpoint, tlog-cosignature) and Sigsum tree heads,
with python3-cryptography. Keys are pinned in sources.toml; a signature that does not verify is an error, not a warning."""
import base64, hashlib, struct
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def ed25519_key(hex_or_b64):
    raw = bytes.fromhex(hex_or_b64) if len(hex_or_b64) == 64 else base64.b64decode(hex_or_b64)
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)

def note_key_id(name, pubkey_raw, alg=0x01):
    """4-byte key hash of a note key: SHA-256(name || '\\n' || alg || pubkey)[:4]. alg 0x01 = Ed25519, 0x04 = cosignature/v1."""
    return hashlib.sha256(name.encode() + b"\n" + bytes([alg]) + pubkey_raw).digest()[:4]

def split_note(text):
    """-> (signed text incl. trailing newline, [(name, sig bytes)])"""
    body, _, sigs = text.partition("\n\n")
    out = []
    for line in sigs.splitlines():
        if line.startswith("— "):
            _, name, b64 = line.split(" ", 2)
            out.append((name, base64.b64decode(b64)))
    return body + "\n", out

def verify_checkpoint(text, origin, log_key_raw, cosigners=None):
    """Verify the log's Ed25519 note signature on a tlog checkpoint; optionally count valid witness cosignatures
    (cosignature/v1) among the given {name: pubkey_raw}. Returns the number of valid cosignatures."""
    body, sigs = split_note(text)
    if not body.startswith(origin + "\n"): raise ValueError(f"checkpoint origin is not {origin}")
    log_sigs = [s for n, s in sigs if n == origin and s[:4] == note_key_id(origin, log_key_raw)]
    if not log_sigs: raise ValueError(f"no signature by the pinned key for {origin}")
    ed25519.Ed25519PublicKey.from_public_bytes(log_key_raw).verify(log_sigs[0][4:], body.encode())  # raises InvalidSignature
    ok = 0
    for name, sig in sigs:
        if name == origin or not cosigners or name not in cosigners: continue
        pub = cosigners[name]
        if sig[:4] != note_key_id(name, pub, 0x04) or len(sig) != 4 + 8 + 64: continue
        t = struct.unpack(">Q", sig[4:12])[0]
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig[12:], f"cosignature/v1\ntime {t}\n".encode() + body.encode()); ok += 1
        except InvalidSignature: raise ValueError(f"bad cosignature from {name}")
    return ok

def verify_rekor_v1_sth(note_text, pem):
    """Rekor v1 signed tree head: a note 'rekor.sigstore.dev - <treeID>\\n<size>\\n<root b64>\\n' with a key-id-prefixed
    ECDSA P-256/SHA-256 DER signature. Returns (tree_id, size, root bytes)."""
    body, sigs = split_note(note_text)
    key = serialization.load_pem_public_key(pem.encode())
    origin, size, root = body.split("\n")[:3]
    if not sigs: raise ValueError("unsigned tree head")
    key.verify(sigs[0][1][4:], body.encode(), ec.ECDSA(hashes.SHA256()))
    return origin.split(" - ")[1], int(size), base64.b64decode(root)

def verify_sigsum_tree_head(text, log_key_hex, witnesses=None):
    """Sigsum get-tree-head: size=, root_hash=, signature= (Ed25519 over the checkpoint text
    'sigsum.org/v1/tree/<log key hash>\\n<size>\\n<root b64>\\n'), cosignature=<key hash> <time> <sig> lines
    (Ed25519 over 'cosignature/v1\\ntime <t>\\n' + checkpoint). witnesses: {key hash hex: pubkey hex}.
    Returns (size, root bytes, valid cosignature count)."""
    kv = {}
    cosigs = []
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if k == "cosignature": cosigs.append(v.split())
        else: kv[k] = v
    size, root = int(kv["size"]), bytes.fromhex(kv["root_hash"])
    log_key = bytes.fromhex(log_key_hex)
    checkpoint = f"sigsum.org/v1/tree/{hashlib.sha256(log_key).hexdigest()}\n{size}\n{base64.b64encode(root).decode()}\n"
    ed25519.Ed25519PublicKey.from_public_bytes(log_key).verify(bytes.fromhex(kv["signature"]), checkpoint.encode())
    ok = 0
    for key_hash, t, sig in cosigs:
        pub = (witnesses or {}).get(key_hash)
        if not pub: continue
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(bytes.fromhex(sig), f"cosignature/v1\ntime {t}\n{checkpoint}".encode()); ok += 1
    return size, root, ok

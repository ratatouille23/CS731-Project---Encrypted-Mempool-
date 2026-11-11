"""Research-only threshold ElGamal KEM + AES-GCM DEM.

The threshold protocol (Feldman commitments, Shamir polynomials, partial
ElGamal decryption, Schnorr randomness proofs, Chaum-Pedersen equality-of-
log proofs, and Lagrange combination) is implemented here, not outsourced to
an existing threshold-encryption library. Low-level AEAD uses cryptography.

This is NOT a proof of IND-CCA2 security or production-ready code; see SECURITY.md.
"""
from __future__ import annotations

import hashlib
import hmac
from functools import lru_cache
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# RFC 3526 2048-bit MODP group (group 14).  p=2q+1, with p and q prime.
# We use g=4 in the order-q quadratic-residue subgroup.
P = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)
Q = (P - 1) // 2
G = 4
GROUP_BYTES = (P.bit_length() + 7) // 8
SCALAR_BYTES = (Q.bit_length() + 7) // 8
VERSION = 1


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bint(number: int, length: int = GROUP_BYTES) -> bytes:
    return number.to_bytes(length, "big")


def rnd() -> int:
    return secrets.randbelow(Q - 1) + 1


def jacobi_symbol(a: int, n: int) -> int:
    """Iterative Jacobi symbol. For prime P it equals the Legendre symbol.

    This checks subgroup membership without a 2047-bit modular exponentiation.
    P is the hard-coded safe prime; a Jacobi value of +1 for a nonzero residue
    means membership in its unique order-Q quadratic-residue subgroup.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("Jacobi denominator must be a positive odd integer")
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def member(x: int, *, allow_identity: bool = False) -> bool:
    return (type(x) is int and 1 <= x < P and (allow_identity or x != 1)
            and jacobi_symbol(x, P) == 1)


def field_hash(domain: str, *items: bytes) -> int:
    h = hashlib.sha512()
    data = domain.encode()
    h.update(len(data).to_bytes(4, "big") + data)
    for item in items:
        h.update(len(item).to_bytes(4, "big") + item)
    return int.from_bytes(h.digest(), "big") % Q


@dataclass(frozen=True)
class Share:
    index: int
    secret: int


@dataclass(frozen=True)
class PublicKey:
    y: int
    commitments: tuple[int, ...]
    n: int
    t: int

    @lru_cache(maxsize=512)
    def share_public(self, index: int) -> int:
        if not 1 <= index <= self.n:
            raise ValueError("Invalid shareholder index")
        value = 1
        for power, comm in enumerate(self.commitments):
            value = (value * pow(comm, pow(index, power, Q), P)) % P
        return value


def keygen(n: int = 16, t: int = 11) -> tuple[PublicKey, list[Share]]:
    """Dealer-assisted key generation, with Feldman verification commitments.

    This is NOT distributed key generation (DKG). Secret exists at dealer setup.
    """
    if not (2 <= t <= n < 128):
        raise ValueError("Require 2 <= t <= n < 128")
    coefs = [rnd()] + [secrets.randbelow(Q) for _ in range(t - 1)]
    commitments = tuple(pow(G, x, P) for x in coefs)
    pub = PublicKey(commitments[0], commitments, n, t)
    shares: list[Share] = []
    for idx in range(1, n + 1):
        secret = 0
        for coef in reversed(coefs):
            secret = (secret * idx + coef) % Q
        share = Share(idx, secret)
        if not verify_key_share(pub, share):
            raise ArithmeticError("Feldman share consistency failed")
        shares.append(share)
    return pub, shares


def verify_key_share(pub: PublicKey, share: Share) -> bool:
    if not 1 <= share.index <= pub.n or not 0 <= share.secret < Q:
        return False
    return hmac.compare_digest(bint(pow(G, share.secret, P)), bint(pub.share_public(share.index)))


def envelope_core(env: dict) -> dict:
    return {key: env[key] for key in ("version", "u", "nonce", "payload", "metadata")}


ENVELOPE_KEYS = frozenset(("version", "u", "nonce", "payload", "metadata", "rand_proof", "txid"))
PROOF_KEYS = frozenset(("a", "z"))


def canonical_hex_integer(s: str) -> int:
    """Reject alternate encodings of the same group/scalar element."""
    if not isinstance(s, str) or not s.startswith("0x"):
        raise ValueError("Expected lowercase canonical hexadecimal integer")
    value = int(s, 16)
    if hex(value) != s:
        raise ValueError("Noncanonical hexadecimal integer")
    return value


def envelope_unsigned(env: dict) -> dict:
    # Hash decoded mathematical values, never attacker-supplied extra keys or
    # alternative string encodings. validate_envelope additionally enforces
    # exact schemas and canonical encodings before accepting an envelope.
    proof = env["rand_proof"]
    return {**{**envelope_core(env), "u": hex(canonical_hex_integer(env["u"]))},
            "rand_proof": {"a": hex(canonical_hex_integer(proof["a"])),
                           "z": hex(canonical_hex_integer(proof["z"]))}}


def envelope_id(env: dict) -> str:
    return digest(canonical(envelope_unsigned(env)))


def aad_for(env: dict) -> bytes:
    return canonical({"version": env["version"], "u": env["u"], "metadata": env["metadata"]})


def derive_key(shared: int, u: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"ShieldedMempool-KEM-v1", info=b"ElGamal-AES256GCM" + bint(u)).derive(bint(shared))


def encrypt(pub: PublicKey, plaintext: bytes, metadata: dict | None = None, *, pad_to: int = 0) -> dict:
    """Encrypt payload; NIZK binds proof of known randomness to complete ciphertext.

    Padding is inside AEAD: four-byte plaintext length + message + random pad.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if len(plaintext) > 2**32 - 1:
        raise ValueError("Message too long")
    r = rnd()
    u = pow(G, r, P)
    shared = pow(pub.y, r, P)
    material = len(plaintext).to_bytes(4, "big") + plaintext
    if pad_to and len(material) < pad_to:
        material += secrets.token_bytes(pad_to - len(material))
    env = {"version": VERSION, "u": hex(u), "nonce": secrets.token_hex(12), "payload": "", "metadata": metadata or {}}
    nonce = bytes.fromhex(env["nonce"])
    env["payload"] = AESGCM(derive_key(shared, u)).encrypt(nonce, material, aad_for(env)).hex()
    w = rnd()
    a = pow(G, w, P)
    c = field_hash("encrypt-randomness-proof-v1", bint(u), bint(a), canonical(envelope_core(env)))
    env["rand_proof"] = {"a": hex(a), "z": hex((w + c * r) % Q)}
    env["txid"] = envelope_id(env)
    return env


def validate_envelope(env: dict, pub: PublicKey) -> bool:
    """PUBLIC pre-decryption check; rejects related ciphertexts without fresh r proof.

    Caution: the proof is Fiat-Shamir Schnorr in the ROM, not a general CCA2 proof.
    """
    try:
        if not isinstance(env, dict) or set(env) != ENVELOPE_KEYS:
            return False
        if not isinstance(env.get("rand_proof"), dict) or set(env["rand_proof"]) != PROOF_KEYS:
            return False
        if type(env.get("version")) is not int or env["version"] != VERSION:
            return False
        if not isinstance(env.get("metadata"), dict):
            return False
        u = canonical_hex_integer(env["u"])
        a = canonical_hex_integer(env["rand_proof"]["a"])
        z = canonical_hex_integer(env["rand_proof"]["z"])
        if not isinstance(env.get("txid"), str) or envelope_id(env) != env["txid"]:
            return False
        if not member(u) or not member(a, allow_identity=True) or not 0 <= z < Q:
            return False
        if len(bytes.fromhex(env["nonce"])) != 12 or len(bytes.fromhex(env["payload"])) < 20:
            return False
        if len(canonical(env["metadata"])) > 4096:
            return False
        c = field_hash("encrypt-randomness-proof-v1", bint(u), bint(a), canonical(envelope_core(env)))
        return pow(G, z, P) == (a * pow(u, c, P)) % P
    except (KeyError, ValueError, TypeError, OverflowError):
        return False


def partial_decrypt(pub: PublicKey, share: Share, env: dict, block_hash: str, *,
                    validated: bool = False, share_checked: bool = False) -> dict:
    """Optional trusted fast path is only for nodes that previously verified the
    exact hash-bound block and their own secret share. External callers recheck.
    """
    if not validated and not validate_envelope(env, pub):
        raise ValueError("Malformed ciphertext, including randomness proof")
    if not share_checked and not verify_key_share(pub, share):
        raise ValueError("Invalid key share")
    u = int(env["u"], 16)
    d = pow(u, share.secret, P)
    v = pub.share_public(share.index)
    w = rnd()
    a, b = pow(G, w, P), pow(u, w, P)
    c = field_hash("partial-decryption-dleq-v1", bint(G), bint(v), bint(u), bint(d), bint(a), bint(b),
                   block_hash.encode(), env["txid"].encode(), share.index.to_bytes(4, "big"))
    return {"index": share.index, "txid": env["txid"], "d": hex(d),
            "proof": {"a": hex(a), "b": hex(b), "z": hex((w + c * share.secret) % Q)}}


def verify_partial(pub: PublicKey, env: dict, block_hash: str, part: dict) -> bool:
    try:
        idx = int(part["index"])
        if not 1 <= idx <= pub.n or part["txid"] != env["txid"]:
            return False
        u, d = int(env["u"], 16), int(part["d"], 16)
        a, b, z = (int(part["proof"][k], 16) for k in ("a", "b", "z"))
        v = pub.share_public(idx)
        if not all(member(x, allow_identity=True) for x in (d, a, b)) or not 0 <= z < Q:
            return False
        c = field_hash("partial-decryption-dleq-v1", bint(G), bint(v), bint(u), bint(d), bint(a), bint(b),
                       block_hash.encode(), env["txid"].encode(), idx.to_bytes(4, "big"))
        return (pow(G, z, P) == a * pow(v, c, P) % P and
                pow(u, z, P) == b * pow(d, c, P) % P)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def lagrange_at_zero(indices: list[int]) -> dict[int, int]:
    if len(indices) != len(set(indices)) or not indices or any(i <= 0 for i in indices):
        raise ValueError("Indices must be unique positive integers")
    result: dict[int, int] = {}
    for i in indices:
        num, den = 1, 1
        for j in indices:
            if i != j:
                num = num * (-j) % Q
                den = den * (i - j) % Q
        result[i] = num * pow(den, -1, Q) % Q
    return result


def combine_shared(pub: PublicKey, env: dict, block_hash: str, parts: list[dict], *, preverified: bool = False) -> int:
    if len(parts) < pub.t:
        raise ValueError(f"Need at least {pub.t} shares")
    selected = parts[:pub.t]
    indices = [int(p["index"]) for p in selected]
    if len(set(indices)) != pub.t:
        raise ValueError("Duplicate share indices")
    if not preverified:
        for p in selected:
            if not verify_partial(pub, env, block_hash, p):
                raise ValueError(f"Invalid partial decryption from node {p['index']}")
    coeff = lagrange_at_zero(indices)
    value = 1
    for part in selected:
        i = part["index"]
        value = value * pow(int(part["d"], 16), coeff[i], P) % P
    return value


def decrypt_with_shared(env: dict, shared: int) -> bytes:
    u = int(env["u"], 16)
    try:
        opened = AESGCM(derive_key(shared, u)).decrypt(bytes.fromhex(env["nonce"]), bytes.fromhex(env["payload"]), aad_for(env))
    except InvalidTag as exc:
        raise ValueError("AEAD tag failed") from exc
    if len(opened) < 4:
        raise ValueError("Invalid plaintext framing")
    msg_len = int.from_bytes(opened[:4], "big")
    if msg_len > len(opened) - 4:
        raise ValueError("Invalid plaintext length")
    return opened[4:4 + msg_len]


def decrypt(pub: PublicKey, env: dict, block_hash: str, parts: list[dict]) -> bytes:
    return decrypt_with_shared(env, combine_shared(pub, env, block_hash, parts))


def public_as_json(pub: PublicKey) -> dict:
    return {"y": hex(pub.y), "commitments": [hex(c) for c in pub.commitments], "n": pub.n, "t": pub.t}


def public_from_json(data: dict) -> PublicKey:
    return PublicKey(int(data["y"], 16), tuple(int(c, 16) for c in data["commitments"]), data["n"], data["t"])

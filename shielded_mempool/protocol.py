"""Signed fixed-order block certificates and ciphertext validation.

Quorum signatures simulate ORDER FINALITY, not BFT consensus. An ordering
service chooses the batch and obtains at least t signatures from committee
processes; honest nodes never attest two different block hashes at a height.
"""
from __future__ import annotations
import base64
from typing import Any
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .crypto import canonical, digest, PublicKey, validate_envelope

GENESIS_HASH = "00" * 32


def transaction_id(tx: dict) -> str:
    if tx.get("kind") == "plain":
        return digest(canonical({"kind": "plain", "data": tx["data"]}))
    return tx["txid"]


def validate_tx(tx: dict, pub: PublicKey, *, allow_naive: bool = False) -> bool:
    if tx.get("kind") == "plain":
        return isinstance(tx.get("data"), str) and len(tx["data"]) <= 1024 * 1024
    if tx.get("kind") == "naive":
        if not allow_naive:
            return False
        from .insecure import naive_validate
        return naive_validate(tx)
    return validate_envelope(tx, pub)


def block_body(height: int, parent_hash: str, transactions: list[dict]) -> dict:
    return {"height": height, "parent_hash": parent_hash, "transactions": transactions}


def block_hash(body: dict) -> str:
    return digest(canonical(body))


def build_block(height: int, parent_hash: str, transactions: list[dict]) -> dict:
    body = block_body(height, parent_hash, transactions)
    return {**body, "block_hash": block_hash(body)}


def validate_block(block: dict, pub: PublicKey, *, allow_naive: bool = False) -> bool:
    try:
        if (not isinstance(block["height"], int) or block["height"] < 1
            or not isinstance(block["parent_hash"], str)
            or len(block["parent_hash"]) != 64
            or block_hash({k: block[k] for k in ("height", "parent_hash", "transactions")}) != block["block_hash"]):
            return False
        txs = block["transactions"]
        if not isinstance(txs, list) or len(txs) == 0 or len(txs) > 4096:
            return False
        if not all(validate_tx(tx, pub, allow_naive=allow_naive) for tx in txs):
            return False
        ids = [transaction_id(tx) for tx in txs]
        if len(set(ids)) != len(ids):
            return False
        # Reject two ciphertexts using the same ElGamal ephemeral u even if
        # their other bytes or txids differ. This is distinct from txid dedup.
        us=[tx['u'] for tx in txs if tx.get('kind') not in ('plain','naive')]
        if len(us) != len(set(us)):
            return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def vote_message(block: dict) -> bytes:
    return canonical({"domain": "ShieldedMempool-FINALITY-v1", "height": block["height"],
                      "parent_hash": block["parent_hash"], "block_hash": block["block_hash"]})


def verify_certificate(block: dict, certificate: list[dict], validator_keys: dict[int, bytes], threshold: int) -> bool:
    if not isinstance(certificate, list) or len(certificate) < threshold:
        return False
    seen: set[int] = set()
    try:
        for row in certificate:
            idx = int(row["index"])
            if idx in seen or idx not in validator_keys:
                return False
            seen.add(idx)
            sig = bytes.fromhex(row["signature"])
            Ed25519PublicKey.from_public_bytes(validator_keys[idx]).verify(sig, vote_message(block))
        return len(seen) >= threshold
    except (KeyError, ValueError, TypeError):
        return False

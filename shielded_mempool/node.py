"""One actual TCP service per committee member (separate OS process)."""
from __future__ import annotations
import asyncio
import json
import time
import hmac
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .crypto import Share, PublicKey, partial_decrypt, verify_key_share, Q
from .insecure import naive_partial
from .protocol import validate_block, vote_message, verify_certificate, block_hash

MAX_REQUEST_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Behavior:
    response_delay_ms: float = 0.0
    withhold: bool = False
    corrupt_share: bool = False


class CommitteeNode:
    def __init__(self, share: Share, pub: PublicKey, sign_key_bytes: bytes,
                 validator_keys: dict[int, bytes], threshold: int, behavior: Behavior, allow_naive: bool = False, admin_token: str | None = None):
        self.share, self.pub = share, pub
        self.signing = Ed25519PrivateKey.from_private_bytes(sign_key_bytes)
        self.validator_keys, self.threshold = validator_keys, threshold
        self.behavior = behavior
        self.allow_naive = allow_naive
        self.admin_token = admin_token
        if not verify_key_share(pub, share):
            raise ValueError('Node was initialized with an invalid secret share')
        self.proposals: dict[int, dict] = {}
        self.finalized: dict[int, str] = {}
        self.validated_block_hashes: set[str] = set()

    def _block_prevalidated(self, block: dict) -> bool:
        """Hash-only cache is unsafe: rehash the supplied body on every RPC.

        Otherwise a malicious sender could change the body but reuse the
        block_hash string of a previously validated block to skip validation.
        """
        try:
            return (block['block_hash'] in self.validated_block_hashes and
                    block_hash({k:block[k] for k in ('height','parent_hash','transactions')})
                    == block['block_hash'])
        except (KeyError,TypeError,ValueError):
            return False

    async def handle(self, req: dict) -> dict:
        op = req.get("op")
        if op == "health":
            return {"ok": True, "node": self.share.index}
        if op == "test_config":
            # Research-only fault-injection control; authenticated by an
            # unpredictable coordinator-held token, bound to localhost TCP.
            token=req.get('admin_token','')
            if not self.admin_token or not isinstance(token,str) or not hmac.compare_digest(token,self.admin_token):
                return {'ok':False,'error':'unauthorized test configuration'}
            delay=float(req.get('response_delay_ms',0.0))
            if not 0 <= delay <= 30_000:
                return {'ok':False,'error':'invalid delay'}
            self.behavior=Behavior(delay,bool(req.get('withhold',False)),bool(req.get('corrupt_share',False)))
            return {'ok':True,'node':self.share.index}
        if self.behavior.response_delay_ms:
            await asyncio.sleep(self.behavior.response_delay_ms / 1000)
        if op == "propose":
            block = req["block"]
            if not self._block_prevalidated(block):
                if not validate_block(block, self.pub, allow_naive=self.allow_naive):
                    return {"ok": False, "error": "invalid block / ciphertext / proof"}
                self.validated_block_hashes.add(block['block_hash'])
            height = block["height"]
            old = self.proposals.get(height)
            if old and old["block_hash"] != block["block_hash"]:
                return {"ok": False, "error": "double proposal at height"}
            if height in self.finalized and self.finalized[height] != block["block_hash"]:
                return {"ok": False, "error": "already finalized different block"}
            self.proposals[height] = block
            sig = self.signing.sign(vote_message(block)).hex()
            return {"ok": True, "index": self.share.index, "signature": sig}
        if op == "epoch_key_release":
            # Intentionally vulnerable benchmark mode. Mimics publishing
            # committee key shares for an entire epoch after one block finalizes.
            if not self.allow_naive:
                return {"ok": False, "error": "epoch-key release disabled in secure protocol"}
            block = req["block"]
            if not validate_block(block, self.pub, allow_naive=True):
                return {"ok": False, "error": "invalid block"}
            saved = self.proposals.get(block["height"])
            if not saved or saved["block_hash"] != block["block_hash"]:
                return {"ok": False, "error": "block not previously proposed"}
            if not verify_certificate(block, req["certificate"], self.validator_keys, self.threshold):
                return {"ok": False, "error": "certificate invalid"}
            return {"ok": True, "index": self.share.index, "key_share": hex(self.share.secret)}
        if op == "release":
            block = req["block"]
            cert = req["certificate"]
            # A node that did not vote can still help decrypt a correctly
            # certified block. This makes FIRST_COMPLETED voting compatible
            # with a different release quorum, and allows restart recovery.
            if not self._block_prevalidated(block):
                if not validate_block(block, self.pub, allow_naive=self.allow_naive):
                    return {"ok": False, "error": "invalid block"}
                self.validated_block_hashes.add(block['block_hash'])
            saved = self.proposals.get(block["height"])
            if saved and saved["block_hash"] != block["block_hash"]:
                return {"ok":False, "error":"local proposal lock conflicts with certificate"}
            if block['height'] in self.finalized and self.finalized[block['height']] != block['block_hash']:
                return {"ok":False, "error":"conflicting finalized block"}
            if not verify_certificate(block, cert, self.validator_keys, self.threshold):
                return {"ok": False, "error": "invalid / insufficient finality certificate"}
            self.finalized[block["height"]] = block["block_hash"]
            if self.behavior.withhold:
                return {"ok": False, "error": "simulated share withholding", "index": self.share.index}
            t0 = time.perf_counter()
            cpu0 = time.process_time()
            parts = []
            for tx in block["transactions"]:
                if tx.get("kind") == "plain":
                    continue
                part = (naive_partial(self.pub, self.share, tx, block["block_hash"])
                        if tx.get("kind")=="naive" else partial_decrypt(
                            self.pub, self.share, tx, block["block_hash"], validated=True, share_checked=True))
                if self.behavior.corrupt_share:
                    part["proof"]["z"] = hex((int(part["proof"]["z"], 16) + 1) % Q)
                parts.append(part)
            return {"ok": True, "index": self.share.index, "parts": parts,
                    "partial_crypto_ms": (time.perf_counter() - t0) * 1000,
                    "partial_crypto_cpu_ms": (time.process_time() - cpu0) * 1000}
        return {"ok": False, "error": "unknown operation"}

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=120.0)
            if len(data) > MAX_REQUEST_BYTES:
                raise ValueError("message too large")
            req = json.loads(data)
            res = await self.handle(req)
        except Exception as exc:
            res = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
        writer.write(json.dumps(res, separators=(",", ":")).encode() + b"\n")
        try:
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


async def serve_node(port: int, share: Share, pub: PublicKey, sign_key_bytes: bytes,
                     validator_keys: dict[int, bytes], threshold: int, behavior: Behavior, allow_naive: bool = False, admin_token: str | None = None) -> None:
    node = CommitteeNode(share, pub, sign_key_bytes, validator_keys, threshold, behavior, allow_naive, admin_token)
    server = await asyncio.start_server(node.handle_connection, "127.0.0.1", port, limit=MAX_REQUEST_BYTES + 1024)
    async with server:
        await server.serve_forever()


def run_node(port: int, share: Share, pub: PublicKey, sign_key_bytes: bytes,
             validator_keys: dict[int, bytes], threshold: int, behavior: Behavior, allow_naive: bool = False, admin_token: str | None = None) -> None:
    asyncio.run(serve_node(port, share, pub, sign_key_bytes, validator_keys, threshold, behavior, allow_naive, admin_token))

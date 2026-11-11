"""Start real 16-node+ committees using multiprocessing and TCP on localhost."""
from __future__ import annotations
import asyncio
import json
import multiprocessing as mp
import socket
import time
import secrets
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from .crypto import keygen, PublicKey
from .node import run_node, Behavior


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def rpc(port: int, request: dict, *, timeout: float = 180.0) -> tuple[dict, int, int]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port, limit=34 * 1024 * 1024), timeout=10)
    payload = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    try:
        writer.write(payload)
        await writer.drain()
        reply = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not reply:
            raise ConnectionError("Empty response")
        return json.loads(reply), len(payload), len(reply)
    finally:
        writer.close()
        await writer.wait_closed()


class Cluster:
    def __init__(self, *, n: int = 16, t: int = 11,
                 offline: set[int] | None = None, withhold: set[int] | None = None,
                 corrupt: set[int] | None = None, delay_ms: float = 0.0,
                 slow: set[int] | None = None, extra_delay_ms: float = 0.0,
                 allow_naive: bool = False, keys_path: str | None = None, key_password: str | None = None):
        if keys_path is not None:
            if not key_password:
                raise ValueError('Provide an encrypted keystore password')
            from .keystore import load_or_create
            self.pub,self.shares,self.signing=load_or_create(keys_path,key_password,n,t)
        else:
            self.pub, self.shares = keygen(n, t)
            self.signing = {i: Ed25519PrivateKey.generate() for i in range(1,n+1)}
        self.allow_naive = allow_naive
        self.admin_token=secrets.token_hex(32)
        self.offline = offline or set()
        self.withhold = withhold or set()
        self.corrupt = corrupt or set()
        self.slow = slow or set()
        self.delay_ms = delay_ms
        self.extra_delay_ms = extra_delay_ms
        self.ports = {i: available_port() for i in range(1, n+1)}
        self.validator_keys = {i: k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for i,k in self.signing.items()}
        self.processes: list[mp.Process] = []

    def start(self) -> "Cluster":
        ctx = mp.get_context("spawn")
        try:
            for share in self.shares:
                idx = share.index
                if idx in self.offline:
                    continue
                priv = self.signing[idx].private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
                behavior = Behavior(self.delay_ms + (self.extra_delay_ms if idx in self.slow else 0),
                                    idx in self.withhold, idx in self.corrupt)
                process = ctx.Process(target=run_node, args=(self.ports[idx], share, self.pub, priv,
                                                               self.validator_keys, self.pub.t, behavior, self.allow_naive, self.admin_token), daemon=True)
                process.start()
                self.processes.append(process)
            end = time.monotonic() + 20
            for idx in self.active_indices:
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", self.ports[idx]), timeout=0.5):
                            break
                    except OSError:
                        if time.monotonic() > end:
                            raise TimeoutError(f"Node {idx} failed to start")
                        time.sleep(0.03)
            return self
        except Exception:
            self.stop()
            raise

    @property
    def active_indices(self) -> list[int]:
        return [i for i in range(1, self.pub.n+1) if i not in self.offline]


    async def configure_faults(self, *, withhold: set[int] | None = None,
                              corrupt: set[int] | None = None,
                              slow: set[int] | None = None,
                              delay_ms: float = 0.0) -> None:
        """Research-only controlled fault injection; uses an authenticated test RPC.

        Does not spawn or terminate nodes. To simulate outage, change
        `cluster.offline` to the indices that should not receive requests.
        """
        withhold=withhold or set();corrupt=corrupt or set();slow=slow or set()
        for i in range(1,self.pub.n+1):
            if i in self.offline and not any(p.is_alive() for p in self.processes):
                raise RuntimeError('committee not running')
        tasks=[rpc(self.ports[i],{
            'op':'test_config','admin_token':self.admin_token,
            'withhold':i in withhold,'corrupt_share':i in corrupt,
            'response_delay_ms':(delay_ms if i in slow else 0.0)
        },timeout=10) for i in range(1,self.pub.n+1)]
        replies=await asyncio.gather(*tasks)
        if not all(r[0].get('ok') for r in replies):
            raise RuntimeError('committee fault injection failed')

    def stop(self) -> None:
        for p in self.processes:
            if p.is_alive():
                p.terminate()
        for p in self.processes:
            p.join(timeout=2)
            if p.is_alive():
                p.kill()
                p.join(timeout=2)
        self.processes.clear()

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()

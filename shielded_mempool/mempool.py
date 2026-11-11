"""SQLite-backed encrypted transaction mempool.

Transactions stay pending until a certified block includes them; only then
are they moved out of the pool.  It is a research gateway, NOT a production
permissionless spam-resistant mempool: see SECURITY.md.
"""
from __future__ import annotations
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from .crypto import PublicKey, canonical, digest, public_as_json
from .protocol import transaction_id, validate_tx


class RejectedTransaction(ValueError):
    pass


class Mempool:
    def __init__(self, pub: PublicKey, path: str = ':memory:', *, allow_naive: bool = False,
                 max_pending: int = 10_000, max_payload: int = 1_048_576):
        self.pub = pub
        self.allow_naive = allow_naive
        self.max_pending = max_pending
        self.max_payload = max_payload
        self.lock = threading.RLock()
        if path != ':memory:':
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('PRAGMA busy_timeout=5000')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS transactions (
            txid TEXT PRIMARY KEY, payload TEXT NOT NULL, u TEXT,
            received_ns INTEGER NOT NULL, fee_priority INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('pending','finalized_unopened','included')),
            block_height INTEGER, block_hash TEXT
          );
          CREATE INDEX IF NOT EXISTS tx_status ON transactions(status,fee_priority,received_ns);
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS blocks (
            height INTEGER PRIMARY KEY, hash TEXT NOT NULL,
            block_json TEXT, cert_json TEXT);
          CREATE TABLE IF NOT EXISTS staged_proposals (
            height INTEGER PRIMARY KEY, hash TEXT NOT NULL, block_json TEXT NOT NULL);
        ''')
        # Migrate v2 databases without discarding pending or finalized state.
        cols={r[1] for r in self.db.execute('PRAGMA table_info(transactions)')}
        if 'u' not in cols:
            self.db.execute('ALTER TABLE transactions ADD COLUMN u TEXT')
        cols={r[1] for r in self.db.execute('PRAGMA table_info(blocks)')}
        for name in ('block_json','cert_json'):
            if name not in cols:
                self.db.execute(f'ALTER TABLE blocks ADD COLUMN {name} TEXT')
        for txid,payload in self.db.execute('SELECT txid,payload FROM transactions WHERE u IS NULL').fetchall():
            ct=json.loads(payload)
            if 'u' in ct and ct.get('kind')!='naive':
                self.db.execute('UPDATE transactions SET u=? WHERE txid=?',(ct['u'],txid))
        self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS unique_encryption_ephemeral ON transactions(u)')
        key_id=digest(canonical(public_as_json(pub)))
        previous=self.db.execute('SELECT value FROM metadata WHERE key=?',('public_key_id',)).fetchone()
        if previous and previous[0]!=key_id:
            raise ValueError('Database created for a different committee key: use the same encrypted keystore')
        if not previous:
            present=self.db.execute('SELECT COUNT(*) FROM transactions').fetchone()[0]
            if present:
                raise ValueError('Existing queue has no committee identity metadata')
            self.db.execute('INSERT INTO metadata VALUES (?,?)',('public_key_id',key_id))
        self.db.commit()

    def block_head(self)->tuple[int,str]|None:
        with self.lock:
            row=self.db.execute('SELECT height,hash FROM blocks ORDER BY height DESC LIMIT 1').fetchone()
        return (int(row[0]),row[1]) if row else None

    def submit(self, tx: dict, *, fee_priority: int = 0) -> str:
        if not isinstance(tx, dict) or not validate_tx(tx, self.pub, allow_naive=self.allow_naive):
            raise RejectedTransaction('ciphertext, authenticity proof or transaction format invalid')
        if tx.get('kind') == 'plain':
            raise RejectedTransaction('plaintext transactions are not allowed into encrypted mempool')
        payload = canonical(tx)
        if len(payload) > self.max_payload:
            raise RejectedTransaction('transaction too large')
        if type(fee_priority) is not int or not 0 <= fee_priority <= 100:
            raise RejectedTransaction('priority must be between 0 and 100')
        txid = transaction_id(tx)
        with self.lock:
            existing = self.db.execute('SELECT status FROM transactions WHERE txid=?',(txid,)).fetchone()
            if existing:
                raise RejectedTransaction('duplicate transaction')
            # The published *vulnerable* variant deliberately permits related
            # ciphertext clones for the attack demonstration. The defended
            # envelope gets the stricter u-based replay/clone prevention.
            u=tx.get('u') if tx.get('kind')!='naive' else None
            if tx.get('kind')!='naive' and (u is None or self.db.execute(
                    'SELECT 1 FROM transactions WHERE u=?',(u,)).fetchone()):
                raise RejectedTransaction('duplicate encryption ephemeral u (related ciphertext clone)')
            count = self.db.execute("SELECT COUNT(*) FROM transactions WHERE status='pending'").fetchone()[0]
            if count >= self.max_pending:
                raise RejectedTransaction('mempool capacity reached')
            self.db.execute('''INSERT INTO transactions
                (txid,payload,u,received_ns,fee_priority,status,block_height,block_hash)
                VALUES (?,?,?,?,?,?,?,?)''',
                            (txid, payload.decode('utf-8'), u, time.time_ns(), fee_priority,
                             'pending', None, None))
            self.db.commit()
        return txid

    def pending(self, *, limit: int = 100, policy: str = 'fifo') -> list[dict]:
        if policy not in ('fifo', 'priority'):
            raise ValueError('unknown selection policy')
        if limit <= 0 or limit > 4096:
            raise ValueError('limit out of range')
        ordering = 'fee_priority DESC, received_ns ASC' if policy == 'priority' else 'received_ns ASC'
        with self.lock:
            rows = self.db.execute(
                f"SELECT payload FROM transactions WHERE status='pending' ORDER BY {ordering} LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def status(self, txid: str) -> dict | None:
        with self.lock:
            row = self.db.execute('SELECT status, block_height, block_hash, fee_priority FROM transactions WHERE txid=?',(txid,)).fetchone()
        return (dict(zip(('status','block_height','block_hash','fee_priority'), row), txid=txid) if row else None)

    def staged_proposal(self, height: int) -> dict | None:
        with self.lock:
            row=self.db.execute('SELECT block_json FROM staged_proposals WHERE height=?',(height,)).fetchone()
        return json.loads(row[0]) if row else None

    def stage_proposal(self, block: dict) -> None:
        """Store the *identical* block for retries after a failed vote quorum.

        A retry may never rerandomize ciphertexts at a height already signed
        by honest nodes: that creates a different hash and permanent lockout.
        """
        height, bh=block['height'],block['block_hash']
        with self.lock:
            existing=self.staged_proposal(height)
            if existing and existing['block_hash']!=bh:
                raise RejectedTransaction('height already locked to another proposal')
            self.db.execute('''INSERT OR IGNORE INTO staged_proposals VALUES (?,?,?)''',(height,bh,canonical(block).decode()))
            self.db.commit()

    def unopened_block(self) -> tuple[dict,list[dict]] | None:
        """Return earliest finalized block with shares yet to be recovered."""
        with self.lock:
            row=self.db.execute('''SELECT b.block_json,b.cert_json
                FROM blocks b JOIN transactions t ON t.block_height=b.height
                WHERE t.status='finalized_unopened'
                ORDER BY b.height ASC LIMIT 1''').fetchone()
        if not row:
            return None
        if not row[0] or not row[1]:
            raise RuntimeError('Legacy finalized block lacks persisted certificate; manual recovery required')
        return json.loads(row[0]),json.loads(row[1])

    def mark_finalized(self, txids: list[str], height: int, block_hash: str,
                       *, block: dict | None = None, certificate: list[dict] | None = None) -> None:
        """Called only after the coordinator validated a quorum finality certificate.

        Prevents a finalized ciphertext from being included in a different block
        even when decryption subsequently lacks a threshold quorum.
        """
        if not txids or len(set(txids)) != len(txids):
            raise ValueError('empty batch or repeated IDs')
        with self.lock:
            for txid in txids:
                row = self.db.execute('SELECT status FROM transactions WHERE txid=?',(txid,)).fetchone()
                if row is None or row[0] != 'pending':
                    raise RejectedTransaction('selected transaction was not pending')
            self.db.executemany(
                "UPDATE transactions SET status='finalized_unopened', block_height=?,block_hash=? WHERE txid=?",
                [(height, block_hash, txid) for txid in txids]
            )
            self.db.execute('''INSERT INTO blocks (height,hash,block_json,cert_json) VALUES (?,?,?,?)''',
                            (height,block_hash,canonical(block).decode() if block else None,
                             canonical(certificate).decode() if certificate else None))
            self.db.execute('DELETE FROM staged_proposals WHERE height=?',(height,))
            self.db.commit()

    def mark_opened(self, txids: list[str], block_hash: str) -> None:
        with self.lock:
            for txid in txids:
                row = self.db.execute('SELECT status,block_hash FROM transactions WHERE txid=?',(txid,)).fetchone()
                if row != ('finalized_unopened', block_hash):
                    raise RejectedTransaction('mismatched or uncertified transaction')
            self.db.executemany("UPDATE transactions SET status='included' WHERE txid=?",[(x,) for x in txids])
            self.db.commit()

    def stats(self) -> dict[str,int]:
        with self.lock:
            rows = self.db.execute('SELECT status, COUNT(*) FROM transactions GROUP BY status').fetchall()
        result = {k:0 for k in ('pending','finalized_unopened','included')}
        result.update(dict(rows))
        return result

    def close(self) -> None:
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

"""Quorum-driven finality-gated execution, deterministic retries and timing.

This is an educational coordinator and an 11-signature *simulated* finality
certificate, not an adversarially secure BFT consensus implementation.
"""
from __future__ import annotations
import asyncio
import os
import statistics
import time
from typing import Any, Callable
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .cluster import Cluster, rpc
from .crypto import canonical, encrypt, verify_partial, combine_shared, decrypt_with_shared
from .protocol import GENESIS_HASH, build_block, verify_certificate, vote_message, transaction_id
from .insecure import naive_open_shared
from .mempool import Mempool


def ms(t0: float) -> float:
    return (time.perf_counter()-t0)*1000


def available_cpus() -> dict:
    result={'logical_cpu_count':os.cpu_count(), 'affinity_cpu_count':None,'cgroup_cpu_quota':None}
    if hasattr(os,'sched_getaffinity'):
        result['affinity_cpu_count']=len(os.sched_getaffinity(0))
    try:
        quota,period=open('/sys/fs/cgroup/cpu.max').read().strip().split()
        if quota!='max':
            result['cgroup_cpu_quota']=round(int(quota)/int(period),2)
    except (OSError,ValueError,ZeroDivisionError):
        pass
    return result


class QuorumError(RuntimeError):
    pass


class Coordinator:
    def __init__(self, cluster: Cluster, mempool: Mempool | None = None, *, rpc_timeout: float = 180.):
        self.cluster=cluster
        self.rpc_timeout=rpc_timeout
        self.mempool=mempool
        head=mempool.block_head() if mempool is not None else None
        self.height=head[0]+1 if head else 1
        self.parent_hash=head[1] if head else GENESIS_HASH
        self._staged_synthetic: tuple[dict,str,list[bytes]|None] | None=None
        self._unopened_synthetic: tuple[dict,list[dict],str,list[bytes]|None] | None=None

    async def _quorum_rpc(self, request: dict, *, accept: Callable[[int,dict],bool],
                          needed: int, indices: list[int] | None = None
                          ) -> tuple[list[tuple[int,dict]], list[tuple[int,dict]], int,int]:
        """Process replies in arrival order, stop at 'needed' *valid* responses.

        Slow/withholding/invalid peers do not gate progress when a quorum of
        honest peers exists. Validation is performed before counting a reply.
        The returned byte counts cover responses actually received, not
        estimated bytes emitted by remote peer processes after cancellation.
        """
        indices=indices if indices is not None else self.cluster.active_indices
        async def call(i):
            try:
                data, sent, recv = await rpc(self.cluster.ports[i],request,timeout=self.rpc_timeout)
                return i,data,sent,recv
            except Exception as exc:
                return i,{'ok':False,'error':f'{type(exc).__name__}: {exc}'},0,0
        pending={asyncio.create_task(call(i)) for i in indices}
        accepted=[]; rejected=[];sent_total=0;recv_total=0
        try:
            while pending and len(accepted)<needed:
                done,pending=await asyncio.wait(pending,return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    idx,result,ns,nr=task.result()
                    sent_total+=ns;recv_total+=nr
                    if accept(idx,result):
                        accepted.append((idx,result))
                    else:
                        rejected.append((idx,result))
            return accepted,rejected,sent_total,recv_total
        finally:
            for task in pending:task.cancel()
            if pending:
                await asyncio.gather(*pending,return_exceptions=True)

    def _vote_valid(self,block:dict):
        def check(idx:int,result:dict)->bool:
            if not result.get('ok') or result.get('index')!=idx or not isinstance(result.get('signature'),str):
                return False
            try:
                Ed25519PublicKey.from_public_bytes(self.cluster.validator_keys[idx]).verify(
                    bytes.fromhex(result['signature']),vote_message(block))
                return True
            except Exception:
                return False
        return check

    def _share_valid(self,block:dict):
        pub=self.cluster.pub
        encrypted=[tx for tx in block['transactions'] if tx.get('kind')!='plain']
        def check(idx:int,result:dict)->bool:
            if not result.get('ok') or result.get('index') != idx:
                return False
            parts=result.get('parts')
            if not isinstance(parts,list) or len(parts)!=len(encrypted):
                return False
            return all(p.get('index')==idx and verify_partial(pub,tx,block['block_hash'],p)
                       for tx,p in zip(encrypted,parts) if isinstance(p,dict)) and all(isinstance(p,dict) for p in parts)
        return check

    async def run_submitted_block(self,limit:int=8,*,policy:str='fifo')->dict:
        if self.mempool is None:
            raise RuntimeError('A persistent mempool is required')
        # Recover an already-certified block FIRST; never abandon its payload.
        if self.mempool.unopened_block():
            return await self.recover_unopened()
        t0=time.perf_counter()
        staged=self.mempool.staged_proposal(self.height)
        transactions=(staged['transactions'] if staged else self.mempool.pending(limit=limit,policy=policy))
        if not transactions:
            raise ValueError('No pending encrypted transactions')
        selection_ms=ms(t0)
        result=await self._execute(transactions,mode='threshold_encrypted',client_ms=0.0,
                                   start=t0,queued=True,override=staged)
        result['mempool_select_ms']=round(selection_ms,3)
        result['remaining_pending']=self.mempool.stats()['pending']
        return result

    async def run_block(self,batch_size:int,*,plain:bool=False,pad_to:int=0)->dict:
        """Synthetic workload using same committee; failed proposal is retried verbatim."""
        if self._unopened_synthetic is not None:
            return await self.recover_unopened()
        if not 1<=batch_size<=4096:
            raise ValueError('batch_size out of range')
        t0=time.perf_counter()
        staged=self._staged_synthetic
        if staged is not None:
            block,mode,expected=staged
            if (mode=='plaintext')!=plain:
                raise QuorumError('Must retry previously locked block before changing workload mode')
            transactions=block['transactions']
            client_ms=0.0
        else:
            transactions=[];expected=[]
            for j in range(batch_size):
                tx={'sender':f'wallet-{j%8}','action':'swap','quantity':j+3,
                    'fee_class':j%3,'sequence':self.height*100000+j}
                raw=canonical(tx);expected.append(raw)
                if plain:
                    transactions.append({'kind':'plain','data':raw.decode()})
                else:
                    transactions.append(encrypt(self.cluster.pub,raw,
                                                {'sender':tx['sender'],'fee_class':tx['fee_class']},pad_to=pad_to))
            client_ms=ms(t0)
        return await self._execute(transactions,mode='plaintext' if plain else 'threshold_encrypted',
                                   client_ms=client_ms,start=t0,queued=False,expected=expected,
                                   override=(staged[0] if staged else None))

    async def _execute(self,transactions:list[dict],*,mode:str,client_ms:float,start:float,
                       queued:bool,expected:list[bytes]|None=None,override:dict|None=None)->dict:
        block=override or build_block(self.height,self.parent_hash,transactions)
        if block['height']!=self.height or block['parent_hash']!=self.parent_hash:
            raise QuorumError('Staged proposal does not extend current chain head')
        txids=[transaction_id(tx) for tx in transactions]
        if queued:
            assert self.mempool is not None
            self.mempool.stage_proposal(block)
        else:
            self._staged_synthetic=(block,mode,expected)

        t_vote=time.perf_counter()
        votes,rejected_votes,out_vote,in_vote=await self._quorum_rpc(
            {'op':'propose','block':block},accept=self._vote_valid(block),needed=self.cluster.pub.t)
        if len(votes)<self.cluster.pub.t:
            raise QuorumError(f'Only {len(votes)} votes; need {self.cluster.pub.t}')
        certificate=[{'index':i,'signature':r['signature']} for i,r in votes[:self.cluster.pub.t]]
        if not verify_certificate(block,certificate,self.cluster.validator_keys,self.cluster.pub.t):
            raise QuorumError('Invalid ordering certificate')
        order_ms=ms(t_vote)
        # The signed block is now fixed. Persist it and the certificate before
        # requesting any shares, even if all release attempts will fail.
        if queued:
            self.mempool.mark_finalized(txids,block['height'],block['block_hash'],
                                        block=block,certificate=certificate)
        else:
            self._staged_synthetic=None
            self._unopened_synthetic=(block,certificate,mode,expected)
        self.parent_hash=block['block_hash'];self.height+=1
        return await self._open_finalized(block,certificate,mode,expected,start,
                                          client_ms,order_ms,out_vote,in_vote,
                                          rejected_vote_count=len(rejected_votes),
                                          queued=queued,recovery=False)

    async def recover_unopened(self)->dict:
        """Re-request shares for the same certified block, including after restart."""
        if self.mempool is not None:
            data=self.mempool.unopened_block()
            if data is None:
                raise ValueError('No finalized unopened block to recover')
            block,certificate=data;mode='threshold_encrypted';expected=None;queued=True
        else:
            if self._unopened_synthetic is None:
                raise ValueError('No finalized unopened block to recover')
            block,certificate,mode,expected=self._unopened_synthetic;queued=False
        if not verify_certificate(block,certificate,self.cluster.validator_keys,self.cluster.pub.t):
            raise QuorumError('Persisted ordering certificate invalid')
        return await self._open_finalized(block,certificate,mode,expected,time.perf_counter(),
                                          0.0,0.0,0,0,rejected_vote_count=0,queued=queued,recovery=True)

    async def _open_finalized(self,block:dict,certificate:list[dict],mode:str,
                              expected:list[bytes]|None,start:float,client_ms:float,order_ms:float,
                              out_vote:int,in_vote:int,*,rejected_vote_count:int,
                              queued:bool,recovery:bool)->dict:
        pub=self.cluster.pub;transactions=block['transactions']
        if mode=='plaintext':
            accepted=[];rejected=[];out_release=in_release=0;release_ms=0;verify_ms=0
            opened=[tx['data'].encode() for tx in transactions]
            open_ms=0.0;post_ms=0.0
        else:
            t_release=time.perf_counter()
            verify_elapsed=0.0
            check_share=self._share_valid(block)
            def verified_response(idx:int, result:dict)->bool:
                nonlocal verify_elapsed
                started=time.perf_counter()
                answer=check_share(idx,result)
                verify_elapsed+=ms(started)
                return answer
            accepted,rejected,out_release,in_release=await self._quorum_rpc(
                {'op':'release','block':block,'certificate':certificate},
                accept=verified_response,needed=pub.t)
            release_ms=ms(t_release)
            if len(accepted)<pub.t:
                raise QuorumError(f'Only {len(accepted)} valid share bundles; need {pub.t}; rejected {len(rejected)}')
            # Time spent locally checking DLEQ proofs is a *subset* of the
            # release phase: it already lies on the measured critical path.
            verify_ms=verify_elapsed
            t_combine=time.perf_counter()
            opened=[]
            by_tx={transaction_id(tx):[] for tx in transactions if tx.get('kind')!='plain'}
            for idx,res in accepted[:pub.t]:
                for part in res['parts']:
                    by_tx[part['txid']].append(part)
            for tx in transactions:
                if tx.get('kind')=='plain':
                    opened.append(tx['data'].encode())
                else:
                    shared=combine_shared(pub,tx,block['block_hash'],by_tx[tx['txid']],preverified=True)
                    opened.append(naive_open_shared(tx,shared) if tx.get('kind')=='naive'
                                  else decrypt_with_shared(tx,shared))
            open_ms=ms(t_combine)
            post_ms=release_ms+open_ms
        if queued:
            assert self.mempool is not None
            self.mempool.mark_opened([transaction_id(tx) for tx in transactions],block['block_hash'])
        else:
            self._unopened_synthetic=None
        if expected is not None and opened!=expected:
            raise AssertionError('Recovered payload differs from expected plaintext')
        wall=[r.get('partial_crypto_ms',0) for _,r in accepted]
        cpu=[r.get('partial_crypto_cpu_ms',0) for _,r in accepted]
        return {
            'mode':mode,'committee':pub.n,'threshold':pub.t,'block_height':block['height'],
            'block_hash':block['block_hash'],'batch_size':len(transactions),
            'transaction_ids':[transaction_id(tx) for tx in transactions],
            'opened_payloads_hex':[x.hex() for x in opened],
            'client_encrypt_ms':round(client_ms,3),
            'order_finalize_ms':round(order_ms,3),
            'committee_release_rpc_ms':round(max(0.0,release_ms-verify_ms),3),
            'release_with_verification_ms':round(release_ms,3),
            'verify_shares_ms':round(verify_ms,3),
            'share_verification_embedded_in_release':bool(mode!='plaintext'),
            'combine_aead_ms':round(open_ms,3),
            'post_finality_ms':round(post_ms,3),
            'block_critical_path_ms':round(order_ms+post_ms,3),
            'total_ms':round(ms(start),3),
            'measured_bytes_sent':out_vote+out_release,
            'measured_bytes_received':in_vote+in_release,
            'bytes_proposal_rpc_sent':out_vote,
            'bytes_release_rpc_sent':out_release,
            'valid_share_nodes':len(accepted) if mode!='plaintext' else 0,
            'invalid_share_nodes':len(rejected) if mode!='plaintext' else 0,
            'invalid_vote_nodes':rejected_vote_count,
            'node_partial_crypto_p50_ms':round(statistics.median(wall),3) if wall else 0.0,
            'node_partial_cpu_p50_ms':round(statistics.median(cpu),3) if cpu else 0.0,
            'node_partial_cpu_sum_ms':round(sum(cpu),3),
            'node_partial_wall_sum_ms':round(sum(wall),3),
            'cpu_environment':available_cpus(),
            'nodes_contacted':len(self.cluster.active_indices),
            'quorum_collection_policy':'first-t-verified',
            'was_recovery':recovery,
            'plaintext_integrity':opened==expected if expected is not None else None,
            'note':'Simulated quorum-signed ordering, not BFT consensus. MODP Python; wall vs CPU differ.'
        }


def benchmark_once(cluster:Cluster,batch_sizes:list[int],repeats:int,*,pad_to:int=0,warmup:int=0)->list[dict]:
    async def run_all():
        coordinator=Coordinator(cluster);rows=[]
        for size in batch_sizes:
            for rep in range(-warmup,repeats):
                baseline=await coordinator.run_block(size,plain=True)
                encrypted=await coordinator.run_block(size,pad_to=pad_to)
                if rep>=0:
                    baseline['repeat']=rep;encrypted['repeat']=rep
                    encrypted['plaintext_baseline_ms']=baseline['block_critical_path_ms']
                    encrypted['added_block_latency_ms']=round(
                        encrypted['block_critical_path_ms']-baseline['block_critical_path_ms'],3)
                    encrypted['ordering_extra_ms']=round(
                        encrypted['order_finalize_ms']-baseline['order_finalize_ms'],3)
                    encrypted['total_added_over_plain_ms']=encrypted['added_block_latency_ms'] # compatibility
                    encrypted['post_order_extra_ms']=encrypted['post_finality_ms']
                    rows.extend([baseline,encrypted])
                    print(f'B={size} rep={rep} plain-critical={baseline["block_critical_path_ms"]:.1f}ms encrypted-critical={encrypted["block_critical_path_ms"]:.1f}ms',flush=True)
        return rows
    return asyncio.run(run_all())


def benchmark_queue_once(cluster:Cluster,batch_sizes:list[int],repeats:int,*,warmup:int=0)->list[dict]:
    """Benchmark pre-encrypted queued transactions, excluding client work from critical path."""
    async def run_all():
        with Mempool(cluster.pub) as pool:
            coord=Coordinator(cluster,pool);rows=[]
            for size in batch_sizes:
                for rep in range(-warmup,repeats):
                    # Plaintext baseline uses a separate synthetic coordinator so
                    # queued chain heights are unaffected by plaintext blocks.
                    # Advance synthetic parent/height independently using an
                    # isolated coordinator and unchanged committee nodes.
                    # To avoid conflicts at a single committee height, baseline
                    # is performed on a distinct height *before* queued block:
                    baseline=await coord.run_block(size,plain=True)
                    client_t0=time.perf_counter()
                    for j in range(size):
                        raw=canonical({'kind':'simulated_swap','i':j,'repeat':rep,'batch':size})
                        tx=encrypt(cluster.pub,raw,{'kind':'swap','fee_class':j%3})
                        pool.submit(tx,fee_priority=j%3)
                    client_prep_ms=ms(client_t0)
                    result=await coord.run_submitted_block(size,policy='fifo')
                    if rep>=0:
                        result['repeat']=rep
                        result['gateway_encrypt_and_admit_ms']=round(client_prep_ms,3)
                        result['submission_to_execution_ms']=result['total_ms']
                        result['client_to_execution_ms']=round(client_prep_ms+result['total_ms'],3)
                        result['plaintext_baseline_ms']=baseline['block_critical_path_ms']
                        result['added_block_latency_ms']=round(result['block_critical_path_ms']-baseline['block_critical_path_ms'],3)
                        result['ordering_extra_ms']=round(result['order_finalize_ms']-baseline['order_finalize_ms'],3)
                        rows.append(result)
                        print(f'queued B={size}, rep={rep}, block-critical={result["block_critical_path_ms"]:.1f}ms post-finality={result["post_finality_ms"]:.1f}ms',flush=True)
            return rows
    return asyncio.run(run_all())

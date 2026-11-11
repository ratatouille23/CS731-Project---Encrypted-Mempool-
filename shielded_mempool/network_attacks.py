"""Integrated demonstrations over actual node TCP services.

USENIX Security 2024: ciphertext malleability / selective batch privacy.
F3B AFT 2023: per-transaction release after fixed ordering.
BEAT-MEV USENIX 2025: pending privacy and ciphertext-index concerns.
This demonstration reproduces *attack classes*, NOT a specific upstream bug.
"""
from __future__ import annotations
import asyncio
import copy
from .crypto import P,Q,encrypt,envelope_id,lagrange_at_zero
from .cluster import Cluster,rpc
from .engine import Coordinator
from .insecure import naive_encrypt,mutate_xor,xor_bytes,mask
from .mempool import Mempool,RejectedTransaction
from .protocol import build_block,GENESIS_HASH
from .attacks import clone_attack_variants


async def _multicast(cl:Cluster,req:dict)->list[dict]:
    results=await asyncio.gather(*(rpc(cl.ports[i],req) for i in cl.active_indices),return_exceptions=True)
    return [item[0] for item in results if not isinstance(item,BaseException)]


async def _vulnerable_demo(cl:Cluster)->dict:
    pub=cl.pub
    victim=b'SWAP 100 TOKEN_A -> TOKEN_B (SECRET)'
    original=naive_encrypt(pub,victim,{'source':'victim'})
    delta=bytes([0x11])+bytes(len(victim)-1)
    modified=mutate_xor(original,delta)
    with Mempool(pub,allow_naive=True) as pool:
        pool.submit(original,fee_priority=0)
        pool.submit(modified,fee_priority=100)
        coord=Coordinator(cl,pool)
        # The attack ciphertext wins priority; original remains excluded/pending.
        row=await coord.run_submitted_block(1,policy='priority')
        included_plain=bytes.fromhex(row['opened_payloads_hex'][0])
        recovered=xor_bytes(included_plain,delta)
        victim_still_pending=(pool.status(original['txid'])['status']=='pending')
        # This corresponds to the epoch-key-release variant in 2024 attacks:
        # all shares are released for one finalized block, opening other ciphertexts.
        cert_block=build_block(1,GENESIS_HASH,[modified])
        votes=await _multicast(cl,{'op':'propose','block':cert_block})
        cert=[{'index':v['index'],'signature':v['signature']} for v in votes if v.get('ok')][:pub.t]
        shares=await _multicast(cl,{'op':'epoch_key_release','block':cert_block,'certificate':cert})
        accepted=shares[:pub.t]
        keys={int(r['index']):int(r['key_share'],16) for r in accepted}
        lag=lagrange_at_zero(list(keys))
        secret=sum(keys[i]*lag[i] for i in keys)%Q
        shared=pow(int(original['u'],16),secret,P)
        recovered_epoch=xor_bytes(bytes.fromhex(original['masked']),mask(shared,len(victim)))
        return {
            'committee_nodes':pub.n, 'threshold':pub.t,
            'malicious_ciphertext_selected':row['transaction_ids']==[modified['txid']],
            'original_victim_excluded_and_pending':victim_still_pending,
            'malleability_original_recovered':recovered==victim,
            'epoch_key_shares_released':len(keys),
            'epoch_key_attack_recovered_excluded':recovered_epoch==victim,
            'finality_before_early_release':True,
            'included_block_latency_ms':row['total_ms'],
            'attack_description':'Naive XOR ciphertext admits related-ciphertext substitutions; a separate naive epoch key-release RPC reveals queued excluded ciphertexts.'
        }


async def _defended_demo(cl:Cluster)->dict:
    pub=cl.pub
    victim=b'SWAP 100 TOKEN_A -> TOKEN_B (SECRET)'
    original=encrypt(pub,victim,{'source':'victim'})
    changed=copy.deepcopy(original)
    payload=bytearray.fromhex(changed['payload']); payload[0]^=1
    changed['payload']=payload.hex()
    changed['txid']=envelope_id(changed)
    with Mempool(pub) as pool:
        pool.submit(original)
        tamper_rejected=False
        try:pool.submit(changed,fee_priority=100)
        except RejectedTransaction:tamper_rejected=True
        # Regression: alternative Schnorr proof encodings used to alter txid
        # without altering a single mathematical proof value (original v2 bug).
        variants=clone_attack_variants(original)
        clone_results={}
        for label,clone in variants.items():
            gateway_rejected=False
            try:
                pool.submit(clone,fee_priority=100)
            except RejectedTransaction:
                gateway_rejected=True
            clone_block=build_block(1,GENESIS_HASH,[clone])
            answers=await _multicast(cl,{'op':'propose','block':clone_block})
            node_rejected=all(not r.get('ok') for r in answers)
            clone_results[label]={
                'distinct_txid':clone['txid']!=original['txid'],
                'same_encryption_ephemeral':clone['u']==original['u'],
                'mempool_rejected':gateway_rejected,
                'committee_rejected':node_rejected}
        # Check nodes also reject it (not just the gateway queue).
        bad_block=build_block(1,GENESIS_HASH,[changed])
        node_replies=await _multicast(cl,{'op':'propose','block':bad_block})
        rejected_by_nodes=all(not r.get('ok') for r in node_replies)
        no_early_shares=all(not r.get('ok') for r in await _multicast(
            cl,{'op':'release','block':bad_block,'certificate':[]}))
        # Submit a different valid encrypted transaction; original remains pending.
        other=encrypt(pub,b'UNRELATED VALID TX')
        pool.submit(other,fee_priority=100)
        coord=Coordinator(cl,pool)
        row=await coord.run_submitted_block(1,policy='priority')
        assert row['transaction_ids']==[other['txid']]
        original_still_pending=(pool.status(original['txid'])['status']=='pending')
        certified=build_block(1,GENESIS_HASH,[other])
        votes=await _multicast(cl,{'op':'propose','block':certified})
        cert=[{'index':v['index'],'signature':v['signature']} for v in votes if v.get('ok')][:pub.t]
        released=await _multicast(cl,{'op':'epoch_key_release','block':certified,'certificate':cert})
        rejects_key_release=all(not r.get('ok') for r in released)
        return {
            'committee_nodes':pub.n,'threshold':pub.t,
            'gateway_rejected_malleated_ciphertext':tamper_rejected,
            'committee_rejected_malleated_proposal':rejected_by_nodes,
            'no_shares_released_without_finality':no_early_shares,
            'victim_remains_pending_after_unrelated_finalized_block':original_still_pending,
            'committee_refused_epoch_key_disclosure':rejects_key_release,
            'defended_block_latency_ms':row['total_ms'],
            'same_u_clone_regression':clone_results,
            'claim_limit':'Checks the specified tampering and epoch-key attacks; not an IND-CCA2 security proof.'
        }


def run_network_attacks(n:int=16,t:int=11)->dict:
    with Cluster(n=n,t=t,allow_naive=True) as cl:
        vulnerable=asyncio.run(_vulnerable_demo(cl))
    with Cluster(n=n,t=t,allow_naive=False) as cl:
        defended=asyncio.run(_defended_demo(cl))
    return {'vulnerable':vulnerable,'defended':defended,'passed':all([
        vulnerable['malicious_ciphertext_selected'],
        vulnerable['original_victim_excluded_and_pending'],
        vulnerable['malleability_original_recovered'],
        vulnerable['epoch_key_attack_recovered_excluded'],
        defended['gateway_rejected_malleated_ciphertext'],
        defended['committee_rejected_malleated_proposal'],
        defended['no_shares_released_without_finality'],
        defended['victim_remains_pending_after_unrelated_finalized_block'],
        defended['committee_refused_epoch_key_disclosure'],
        all(v['distinct_txid'] and v['same_encryption_ephemeral']
            and v['mempool_rejected'] and v['committee_rejected']
            for v in defended['same_u_clone_regression'].values())])}

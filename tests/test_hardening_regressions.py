"""Regression tests for reported 2026-11-10 prototype issues."""
import asyncio
import copy
import time

import pytest

from shielded_mempool.crypto import (P,Q,keygen,encrypt,validate_envelope,
    member,jacobi_symbol,canonical,bint,G,field_hash)
from shielded_mempool.attacks import clone_attack_variants,legacy_unsafe_txid
from shielded_mempool.mempool import Mempool,RejectedTransaction
from shielded_mempool.protocol import build_block,GENESIS_HASH,validate_block
from shielded_mempool.cluster import Cluster
from shielded_mempool.engine import Coordinator,QuorumError


def old_v2_accepts_unchecked_proof_shapes(env,pub):
    """A reproduction of the original permissive validation logic."""
    from shielded_mempool.crypto import envelope_core
    try:
        u=int(env['u'],16);a=int(env['rand_proof']['a'],16);z=int(env['rand_proof']['z'],16)
        if not (member(u) and member(a,allow_identity=True) and 0<=z<Q):
            return False
        c=field_hash('encrypt-randomness-proof-v1', bint(u), bint(a), canonical(envelope_core(env)))
        return old_v2_txid_matches(env) and pow(G,z,P)==(a*pow(u,c,P))%P
    except (ValueError,TypeError,KeyError):return False


def old_v2_txid_matches(env):
    return legacy_unsafe_txid(env)==env['txid']


def test_clone_forms_were_previously_valid_but_now_rejected():
    pub,_=keygen(3,2)
    victim=encrypt(pub,b'secret victim tx')
    assert validate_envelope(victim,pub)
    clones=clone_attack_variants(victim)
    with Mempool(pub) as pool:
        pool.submit(victim,fee_priority=1)
        for name,clone in clones.items():
            assert clone['txid']!=victim['txid'],name
            assert clone['u']==victim['u'],name
            assert old_v2_accepts_unchecked_proof_shapes(clone,pub),name
            assert not validate_envelope(clone,pub),name
            with pytest.raises(RejectedTransaction):
                pool.submit(clone,fee_priority=100)
            assert not validate_block(build_block(1,GENESIS_HASH,[clone]),pub)
        assert [x['txid'] for x in pool.pending(policy='priority')]==[victim['txid']]


def test_unknown_top_level_fields_and_bool_versions_rejected():
    pub,_=keygen(3,2)
    victim=encrypt(pub,b'x')
    extra=copy.deepcopy(victim);extra['ignored']='ignored'
    assert not validate_envelope(extra,pub)
    boolean=copy.deepcopy(victim);boolean['version']=True
    assert not validate_envelope(boolean,pub)


def test_fast_subgroup_check_matches_exponentiation():
    for x in [0,1,2,3,4,5,7,19,P-1,P-2,P//2,P//3]:
        assert (member(x,allow_identity=True)==(1<=x<P and pow(x,Q,P)==1))
        if 1<=x<P:
            assert jacobi_symbol(x,P)==(1 if pow(x,Q,P)==1 else -1)


@pytest.mark.integration
def test_first_t_verified_not_all_nodes():
    # Two *four-second* nodes must not delay three fast honest nodes.
    with Cluster(n=5,t=3,slow={1,2},extra_delay_ms=4000) as cl:
        t0=time.perf_counter()
        row=asyncio.run(Coordinator(cl,rpc_timeout=8).run_block(1))
        elapsed=time.perf_counter()-t0
        assert row['valid_share_nodes']==3
        assert elapsed<3.5, f'Coordinator waited for slow peers: {elapsed:.2f}s'
        assert row['quorum_collection_policy']=='first-t-verified'
        assert row['node_partial_cpu_p50_ms']>0


@pytest.mark.integration
def test_failed_proposal_reuses_identical_block_after_nodes_return():
    with Cluster(n=5,t=3) as cl:
        c=Coordinator(cl)
        # Runtime reachability changes; all five processes are actually alive.
        cl.offline={1,2,3}
        with pytest.raises(QuorumError,match='votes'):
            asyncio.run(c.run_block(1))
        locked=c._staged_synthetic[0]
        assert locked['height']==1
        cl.offline=set()
        row=asyncio.run(c.run_block(1))
        assert row['block_hash']==locked['block_hash']
        assert row['block_height']==1 and row['plaintext_integrity']
        assert c.height==2


@pytest.mark.integration
def test_finalized_unopened_recovery_without_changing_block(tmp_path):
    path=str(tmp_path/'pool.db')
    with Cluster(n=5,t=3,withhold={1,2,3}) as cl:
        with Mempool(cl.pub,path) as pool:
            msg=b'RECOVER ME'
            tx=encrypt(cl.pub,msg)
            pool.submit(tx)
            c=Coordinator(cl,pool)
            with pytest.raises(QuorumError,match='share bundles'):
                asyncio.run(c.run_submitted_block(1))
            assert pool.status(tx['txid'])['status']=='finalized_unopened'
            block,certificate=pool.unopened_block()
            original_hash=block['block_hash']
            assert len(certificate)==3
            # Remove Byzantine withholding with authenticated simulation control.
            asyncio.run(cl.configure_faults())
            fresh=Coordinator(cl,pool)
            assert fresh.height==2
            recovered=asyncio.run(fresh.run_submitted_block(1))
            assert recovered['was_recovery']
            assert recovered['block_hash']==original_hash
            assert bytes.fromhex(recovered['opened_payloads_hex'][0])==msg
            assert pool.status(tx['txid'])['status']=='included'
            assert pool.unopened_block() is None


@pytest.mark.integration
def test_failed_queued_proposal_persists_for_new_coordinator(tmp_path):
    with Cluster(n=5,t=3) as cl:
        with Mempool(cl.pub,str(tmp_path/'pool.sqlite')) as pool:
            tx=encrypt(cl.pub,b'QUEUED RETRY');pool.submit(tx)
            cl.offline={1,2,3}
            with pytest.raises(QuorumError,match='votes'):
                asyncio.run(Coordinator(cl,pool).run_submitted_block(1))
            staged=pool.staged_proposal(1)
            assert staged is not None
            cl.offline.clear()
            retry=asyncio.run(Coordinator(cl,pool).run_submitted_block(1))
            assert retry['block_hash']==staged['block_hash']
            assert retry['plaintext_integrity'] is None
            assert pool.staged_proposal(1) is None
            assert pool.stats()['included']==1

@pytest.mark.integration
def test_cached_block_validation_not_bypassed_by_reusing_hash():
    from shielded_mempool.cluster import rpc
    with Cluster(n=3,t=2) as cl:
        tx=encrypt(cl.pub,b'original')
        block=build_block(1,GENESIS_HASH,[tx])
        accepted=asyncio.run(rpc(cl.ports[1],{'op':'propose','block':block}))[0]
        assert accepted['ok']
        forged=copy.deepcopy(block)
        forged['transactions'][0]['payload']='00'+forged['transactions'][0]['payload'][2:]
        # Attacker leaves known cached block_hash in the request unchanged.
        response=asyncio.run(rpc(cl.ports[1],{'op':'propose','block':forged}))[0]
        assert not response['ok']


@pytest.mark.integration
def test_certified_unopened_survives_process_restart_with_same_keystore(tmp_path):
    path=str(tmp_path/'pending.db');keys=str(tmp_path/'committee.enc')
    pwd='long test passphrase'
    with Cluster(n=3,t=2,withhold={1,2},keys_path=keys,key_password=pwd) as cl:
        with Mempool(cl.pub,path) as pool:
            tx=encrypt(cl.pub,b'CERTIFIED AND PENDING')
            pool.submit(tx)
            with pytest.raises(QuorumError,match='share bundles'):
                asyncio.run(Coordinator(cl,pool).run_submitted_block(1))
            cert_block,cert=pool.unopened_block()
            original_hash=cert_block['block_hash']
    # Nodes have now lost their in-memory vote caches. The same persisted
    # Ed25519 keys and signed finality certificate authorize release.
    with Cluster(n=3,t=2,keys_path=keys,key_password=pwd) as cl:
        with Mempool(cl.pub,path) as pool:
            recovered=asyncio.run(Coordinator(cl,pool).recover_unopened())
            assert recovered['was_recovery']
            assert recovered['block_hash']==original_hash
            assert bytes.fromhex(recovered['opened_payloads_hex'][0])==b'CERTIFIED AND PENDING'
            assert pool.stats()['included']==1


def test_benchmark_percentile_summarization_is_sample_based(tmp_path):
    from shielded_mempool.benchmarking import write_summary
    rows=[]
    for i in range(25):
        rows.append({'mode':'threshold_encrypted','batch_size':1,
                     'block_critical_path_ms':100+i,'post_finality_ms':95+i,
                     'node_partial_cpu_p50_ms':10+i,'repeat':i})
    summary=write_summary(tmp_path,rows)
    assert summary[0]['samples']==25
    assert summary[0]['stats_reliable']
    assert summary[0]['post_finality_ms_p50']==107
    assert summary[0]['post_finality_ms_p95']>summary[0]['post_finality_ms_p50']
    assert (tmp_path/'benchmark_summary.csv').exists()
    assert (tmp_path/'stacked_critical_path.png').exists()


def test_even_valid_alternative_ciphertext_reusing_u_is_not_admitted(monkeypatch):
    import shielded_mempool.crypto as crypto
    pub,_=keygen(3,2)
    # Simulate accidentally or maliciously knowing and reusing the same
    # encryption exponent. Different AEAD nonce/payload -> different txid.
    monkeypatch.setattr(crypto,'rnd',lambda:42)
    a=encrypt(pub,b'trade 1');b=encrypt(pub,b'trade 2')
    assert a['u']==b['u'] and a['txid']!=b['txid']
    assert validate_envelope(a,pub) and validate_envelope(b,pub)
    with Mempool(pub) as pool:
        pool.submit(a)
        with pytest.raises(RejectedTransaction,match='ephemeral'):
            pool.submit(b)
    assert not validate_block(build_block(1,GENESIS_HASH,[a,b]),pub)

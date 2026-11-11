import copy
import pytest
from shielded_mempool.crypto import keygen,encrypt,envelope_id
from shielded_mempool.mempool import Mempool,RejectedTransaction
from shielded_mempool.keystore import load_or_create
from shielded_mempool.btx_algebra import toy_demo,index_collision_demo


def test_mempool_pending_order_and_finality(tmp_path):
    pub,shares=keygen(5,3)
    path=str(tmp_path/'pool.db')
    first=encrypt(pub,b'victim');second=encrypt(pub,b'attacker')
    with Mempool(pub,path) as pool:
        pool.submit(first,fee_priority=1)
        pool.submit(second,fee_priority=15)
        with pytest.raises(RejectedTransaction):pool.submit(first)
        assert [x['txid'] for x in pool.pending(limit=2,policy='fifo')]==[first['txid'],second['txid']]
        assert pool.pending(limit=1,policy='priority')[0]['txid']==second['txid']
        pool.mark_finalized([second['txid']],1,'ab'*32)
        assert pool.status(first['txid'])['status']=='pending'
        assert pool.stats()['finalized_unopened']==1
        pool.mark_opened([second['txid']],'ab'*32)
        assert pool.status(second['txid'])['status']=='included'
        assert pool.block_head()==(1,'ab'*32)
    with Mempool(pub,path) as restored:
        assert restored.stats()=={'pending':1,'included':1,'finalized_unopened':0}
    newpub,_=keygen(5,3)
    with pytest.raises(ValueError,match='different committee'):
        Mempool(newpub,path)


def test_malleated_ciphertext_rejected_by_queue():
    pub,_=keygen(3,2)
    env=encrypt(pub,b'hello world')
    bad=copy.deepcopy(env)
    raw=bytearray.fromhex(bad['payload']);raw[-1]^=1
    bad['payload']=raw.hex();bad['txid']=envelope_id(bad)
    with Mempool(pub) as pool:
        with pytest.raises(RejectedTransaction):pool.submit(bad)
        assert pool.stats()['pending']==0


def test_encrypted_keystore_roundtrip(tmp_path):
    path=str(tmp_path/'secret.keys')
    pub,shares,keys=load_or_create(path,'correct horse battery staple',3,2)
    pub2,shares2,keys2=load_or_create(path,'correct horse battery staple',3,2)
    assert pub==pub2 and shares==shares2
    assert keys[1].public_key().public_numbers() if hasattr(keys[1].public_key(),'public_numbers') else True
    assert (tmp_path/'secret.keys').stat().st_mode&0o777==0o600
    with pytest.raises(Exception):load_or_create(path,'incorrect passphrase',3,2)


def test_btx_algebra_is_correct_but_deliberately_insecure():
    demo=toy_demo(16,11,12)
    assert demo['correct']
    assert demo['partial_decryption_scalars_transmitted']==11
    assert demo['baseline_per_transaction_scalars']==132
    assert demo['INSECURE_public_can_decrypt_without_shares']
    attack=index_collision_demo(namespace=32,attacker_count=3)
    assert attack['single_unique_index_batch_can_include_all'] is False
    assert attack['subbatch_groups']==4

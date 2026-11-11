import copy
import pytest
from shielded_mempool.crypto import (P,Q,G,keygen,encrypt,validate_envelope,envelope_id,
    verify_key_share,partial_decrypt,verify_partial,decrypt,combine_shared,lagrange_at_zero)
from shielded_mempool.attacks import run_malleability_demo, run_epoch_leak_demo
from shielded_mempool.protocol import build_block, validate_block


def test_group_and_shares():
    assert P.bit_length() == 2048
    assert pow(G,Q,P)==1
    pub, ss=keygen(16,11)
    assert all(verify_key_share(pub,s) for s in ss)
    assert len(set(s.secret for s in ss))==16
    assert sum(s.secret*lagrange_at_zero([x.index for x in ss[:11]])[s.index] for s in ss[:11])%Q != 0


def test_threshold_decryption_and_bad_shares():
    pub, ss=keygen(16,11)
    env=encrypt(pub,b'my secret trade',{'sender':'alice'},pad_to=512)
    assert validate_envelope(env,pub)
    proofs=[partial_decrypt(pub,s,env,'block-hash') for s in ss[:11]]
    assert all(verify_partial(pub,env,'block-hash',p) for p in proofs)
    assert decrypt(pub,env,'block-hash',proofs)==b'my secret trade'
    with pytest.raises(ValueError,match='at least'):
        decrypt(pub,env,'block-hash',proofs[:10])
    changed=copy.deepcopy(proofs)
    changed[0]['proof']['z']='0x0'
    assert not verify_partial(pub,env,'block-hash',changed[0])
    with pytest.raises(ValueError,match='Invalid partial'):
        combine_shared(pub,env,'block-hash',changed)
    assert not verify_partial(pub,env,'different-finality-block',proofs[0])


def test_envelope_malleability_rejected():
    pub,_=keygen(16,11)
    env=encrypt(pub,b'do not open',{'sender':'victim'})
    modified=copy.deepcopy(env)
    dat=bytearray.fromhex(modified['payload']);dat[-1]^=1
    modified['payload']=dat.hex()
    modified['txid']=envelope_id(modified)
    assert not validate_envelope(modified,pub)
    block=build_block(1,'00'*32,[modified])
    assert not validate_block(block,pub)


def test_known_attacks():
    a=run_malleability_demo()
    b=run_epoch_leak_demo()
    assert a['naive_attack_recovered_original']
    assert a['defended_related_ciphertext_rejected_before_share_release']
    assert b['excluded_pending_opened_after_epoch_key_release']
    assert b['other_ciphertext_DH_cannot_directly_open_pending']

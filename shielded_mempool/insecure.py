"""DELIBERATELY INSECURE controls, used only for reproducible attacks.

- XOR-masked unauthenticated threshold ElGamal ciphertext is malleable.
- Epoch-wide secret sharing/reconstruction reveals excluded ciphertexts.
Do not use this module in a real cryptographic application.
"""
from __future__ import annotations
import copy
import hashlib
from .crypto import (P,Q,G,GROUP_BYTES,SCALAR_BYTES,PublicKey,Share,rnd,canonical,digest,
                     member,bint,field_hash)


def xor_bytes(a: bytes,b: bytes)->bytes:
    return bytes(x^y for x,y in zip(a,b))


def mask(shared: int,n: int)->bytes:
    seed=shared.to_bytes(GROUP_BYTES,'big')
    return b''.join(hashlib.sha256(b'naive-xor'+seed+i.to_bytes(4,'big')).digest()
                    for i in range((n+31)//32))[:n]


def naive_id(tx:dict)->str:
    return digest(canonical({k:tx[k] for k in ('kind','u','masked','metadata')}))


def naive_encrypt(pub:PublicKey,plaintext:bytes, metadata:dict|None=None)->dict:
    r=rnd()
    u=pow(G,r,P)
    shared=pow(pub.y,r,P)
    tx={'kind':'naive','u':hex(u),'masked':xor_bytes(plaintext,mask(shared,len(plaintext))).hex(),
        'metadata':metadata or {}}
    tx['txid']=naive_id(tx)
    return tx


def naive_validate(tx:dict)->bool:
    try:
        if tx.get('kind')!='naive' or tx['txid']!=naive_id(tx):
            return False
        if not member(int(tx['u'],16)):
            return False
        if not 1<=len(bytes.fromhex(tx['masked']))<=1_048_576:
            return False
        return isinstance(tx['metadata'],dict) and len(canonical(tx['metadata']))<=4096
    except (KeyError,TypeError,ValueError,OverflowError):
        return False


def mutate_xor(tx:dict, delta:bytes)->dict:
    modified=copy.deepcopy(tx)
    data=bytes.fromhex(tx['masked'])
    if len(delta)!=len(data):
        raise ValueError('delta length mismatch')
    modified['masked']=xor_bytes(data,delta).hex()
    modified['txid']=naive_id(modified)
    return modified


def naive_partial(pub:PublicKey,share:Share,tx:dict,block_hash:str)->dict:
    if not naive_validate(tx):
        raise ValueError('invalid naive ciphertext')
    u=int(tx['u'],16)
    d=pow(u,share.secret,P)
    v=pub.share_public(share.index)
    w=rnd(); a,b=pow(G,w,P),pow(u,w,P)
    c=field_hash('partial-decryption-dleq-v1',bint(G),bint(v),bint(u),bint(d),bint(a),bint(b),
                 block_hash.encode(),tx['txid'].encode(),share.index.to_bytes(4,'big'))
    return {'index':share.index,'txid':tx['txid'],'d':hex(d),
            'proof':{'a':hex(a),'b':hex(b),'z':hex((w+c*share.secret)%Q)}}


def naive_open_shared(tx:dict,shared:int)->bytes:
    data=bytes.fromhex(tx['masked'])
    return xor_bytes(data,mask(shared,len(data)))

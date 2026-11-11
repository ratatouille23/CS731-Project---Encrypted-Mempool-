"""Password-encrypted DEVELOPMENT keystore for restarting the same committee.

This holds all committee secrets in one file, so its owner is a trusted dealer.
It is NOT a distributed key-generation solution or a production HSM.
"""
from __future__ import annotations
import json
import os
import secrets
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from .crypto import keygen,Share,PublicKey,public_as_json,public_from_json,verify_key_share,canonical


def _key(password:str,salt:bytes)->bytes:
    if len(password)<12:raise ValueError('keystore password must be at least 12 characters')
    return Scrypt(salt=salt,length=32,n=2**14,r=8,p=1).derive(password.encode('utf-8'))


def load_or_create(path:str,password:str,n:int,t:int):
    location=Path(path)
    if location.exists():
        wrapper=json.loads(location.read_text())
        if wrapper.get('format')!='ShieldedMempool-keys-v1':raise ValueError('invalid key file')
        salt=bytes.fromhex(wrapper['salt']); nonce=bytes.fromhex(wrapper['nonce'])
        raw=AESGCM(_key(password,salt)).decrypt(nonce,bytes.fromhex(wrapper['sealed']),b'ShieldedMempool-keystore-v1')
        doc=json.loads(raw)
        pub=public_from_json(doc['public'])
        if (pub.n,pub.t)!=(n,t):raise ValueError('stored committee dimensions mismatch')
        shares=[Share(int(row['index']),int(row['secret'],16)) for row in doc['shares']]
        if len(shares)!=n or {s.index for s in shares}!=set(range(1,n+1)) or not all(verify_key_share(pub,s) for s in shares):
            raise ValueError('invalid key shares in stored committee')
        keys={int(i):Ed25519PrivateKey.from_private_bytes(bytes.fromhex(v)) for i,v in doc['ed25519'].items()}
        if len(keys)!=n:raise ValueError('incomplete validator signing keystore')
        return pub,shares,keys
    pub,shares=keygen(n,t)
    keys={i:Ed25519PrivateKey.generate() for i in range(1,n+1)}
    doc={'public':public_as_json(pub),'shares':[{'index':s.index,'secret':hex(s.secret)} for s in shares],
         'ed25519':{str(i):key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()).hex() for i,key in keys.items()}}
    salt=secrets.token_bytes(16); nonce=secrets.token_bytes(12)
    sealed=AESGCM(_key(password,salt)).encrypt(nonce,canonical(doc),b'ShieldedMempool-keystore-v1')
    wrapper={'format':'ShieldedMempool-keys-v1','salt':salt.hex(),'nonce':nonce.hex(),'sealed':sealed.hex()}
    location.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(str(location),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:f.write(json.dumps(wrapper,indent=2)+'\n')
    return pub,shares,keys

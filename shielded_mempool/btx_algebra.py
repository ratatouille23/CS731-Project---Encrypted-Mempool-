"""UNSAFE algebra-only reproduction of the BTX batching equations.

This executable *ideal exponent group* model is deliberately NOT cryptography.
It models G1/G2/GT elements by their underlying exponents, so discrete logs
are public and every ciphertext is trivially readable. It is useful for testing
that one partial decryption per party algebraically opens a chosen batch, and
for understanding O(n) vs O(nB) communication, but MUST NOT be deployed.

Based on the mathematical overview in Agarwal et al., BTX (2026):
  sigma = sum_{j=1}^B tau^j * [r_j]_G1
  alpha_i = pairing(sigma, [tau^(Bmax-i+1)]_G2)
  mask_i  = alpha_i - sum_{j != i} pairing([r_j]_G1,
                                        [tau^(j+Bmax-i+1)]_G2)

Real BTX uses pairing-friendly BLS12-381 groups and simulation-extractable
validity proofs. Neither is implemented in this explanatory module.
"""
from __future__ import annotations
import secrets
from dataclasses import dataclass
from .crypto import Q,lagrange_at_zero


@dataclass(frozen=True)
class BTXToyPublic:
    bmax:int
    ek:int
    h:dict[int,int]
    t:int
    n:int


@dataclass(frozen=True)
class BTXToyShare:
    index:int
    powers:tuple[int,...]


def _eval(coeff:list[int],x:int)->int:
    acc=0
    for c in reversed(coeff):acc=(acc*x+c)%Q
    return acc


def toy_keygen(n:int=16,t:int=11,bmax:int=32)->tuple[BTXToyPublic,list[BTXToyShare]]:
    if not 2<=t<=n or not 1<=bmax<=1024:
        raise ValueError('invalid parameters')
    tau=secrets.randbelow(Q-1)+1
    h={j:pow(tau,j,Q) for j in range(1,2*bmax+1) if j!=bmax+1}
    pub=BTXToyPublic(bmax,pow(tau,bmax+1,Q),h,t,n)
    # Dealer shares tau^1,...,tau^Bmax under independent t-1 polynomials.
    powers=[]
    for ell in range(1,bmax+1):
        coeff=[pow(tau,ell,Q)]+[secrets.randbelow(Q) for _ in range(t-1)]
        powers.append(coeff)
    shares=[BTXToyShare(i,tuple(_eval(poly,i) for poly in powers)) for i in range(1,n+1)]
    return pub,shares


def toy_encrypt(pub:BTXToyPublic,m:int)->tuple[int,int]:
    if not 0<=m<Q:raise ValueError('plaintext must be field scalar')
    r=secrets.randbelow(Q-1)+1
    return r,(m+r*pub.ek)%Q


def toy_partial(share:BTXToyShare,cts:list[tuple[int,int]])->int:
    if len(cts)>len(share.powers) or len(cts)<1:raise ValueError('bad batch')
    return sum(share.powers[j]*ct[0] for j,ct in enumerate(cts))%Q


def toy_open(pub:BTXToyPublic,cts:list[tuple[int,int]],shares:list[tuple[int,int]])->list[int]:
    B=len(cts)
    if not 1<=B<=pub.bmax or len(shares)<pub.t:raise ValueError('insufficient shares or batch')
    selected=shares[:pub.t]
    inds=[i for i,_ in selected]
    coeff=lagrange_at_zero(inds)
    sigma=sum(coeff[i]*part for i,part in selected)%Q
    recovered=[]
    for i,(r,v) in enumerate(cts,1):
        alpha=(sigma*pub.h[pub.bmax-i+1])%Q
        nuisance=0
        for j,(other_r,_) in enumerate(cts,1):
            if i!=j:
                idx=j+pub.bmax-i+1
                nuisance=(nuisance+other_r*pub.h[idx])%Q
        mask=(alpha-nuisance)%Q
        recovered.append((v-mask)%Q)
    return recovered


def toy_demo(n:int=16,t:int=11,B:int=8)->dict:
    pub,shares=toy_keygen(n,t,bmax=max(16,B))
    messages=[secrets.randbelow(Q) for _ in range(B)]
    cts=[toy_encrypt(pub,m) for m in messages]
    selected=[(s.index,toy_partial(s,cts)) for s in shares[:t]]
    opened=toy_open(pub,cts,selected)
    # This exploit is always possible in the exponent model: the encryption
    # randomness r is exposed as a scalar rather than an opaque G1 element.
    trivial_decrypt=[(v-r*pub.ek)%Q for r,v in cts]
    return {'correct':opened==messages,'committee':n,'threshold':t,'batch':B,
            'partial_decryption_scalars_transmitted':len(selected),
            'baseline_per_transaction_scalars':t*B,
            'algebraic_reduction_factor':B,
            'INSECURE_public_can_decrypt_without_shares':trivial_decrypt==messages,
            'warning':'Ideal-exponent algebra model ONLY; not deployable pairing-based BTE.'}


def index_collision_demo(namespace:int=32,attacker_count:int=1)->dict:
    """Abstract BEAT-MEV-style index collision, NOT its threshold protocol.

    Victim occupies slot 7. The attacker intentionally uses the same index;
    unique-index batch cannot include both. Greedy sub-batching separates them
    and restores inclusion at increased per-node decryption messages.
    """
    if namespace<8 or attacker_count<1:raise ValueError('invalid scenario')
    assigned=[7]+[7]*attacker_count+[i for i in (2,3,4,5)]
    groups=[]
    for idx in assigned:
        placed=False
        for g in groups:
            if idx not in g:
                g.add(idx);placed=True;break
        if not placed:groups.append({idx})
    return {'victim_index':7,'attacker_colliding_ciphertexts':attacker_count,
            'single_unique_index_batch_can_include_all':len(set(assigned))==len(assigned),
            'subbatch_groups':len(groups),
            'mitigation_can_schedule_all_in_subbatches':True,
            'decryption_messages_per_node_increase_factor':len(groups),
            'caveat':'Index-collision scheduling model, not a BEAT-MEV cryptographic reproduction.'}

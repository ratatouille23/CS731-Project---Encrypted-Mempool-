"""Published-class malleability and epoch-release counterexamples.

The malformed/related ciphertext model matches the class discussed by
Choudhuri et al. (USENIX Security 2024), not a claim of compromising a
current Shutter release. The defensive experiment blocks the SAME transform.
"""
from __future__ import annotations
import copy
import hashlib
import secrets
from .crypto import P, Q, G, GROUP_BYTES, PublicKey, Share, keygen, encrypt, validate_envelope, envelope_id, lagrange_at_zero, rnd, canonical, envelope_core, digest


def xor_bytes(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a,b in zip(x, y))


def expand_mask(shared: int, n: int) -> bytes:
    seed = shared.to_bytes(GROUP_BYTES, 'big')
    return b''.join(hashlib.sha256(b'naive-xor' + seed + i.to_bytes(4,'big')).digest()
                    for i in range((n + 31) // 32))[:n]


def naive_encrypt(pub: PublicKey, plaintext: bytes) -> dict:
    r = rnd()
    u = pow(G, r, P)
    shared = pow(pub.y, r, P)
    return {"u": hex(u), "masked": xor_bytes(plaintext, expand_mask(shared, len(plaintext))).hex()}


def naive_open(envelope: dict, shares: list[Share]) -> bytes:
    """Recover the DH group element from threshold partials, without proofs."""
    selected = shares
    coeff = lagrange_at_zero([x.index for x in selected])
    u = int(envelope['u'], 16)
    dh = 1
    for share in selected:
        dh = dh * pow(pow(u, share.secret, P), coeff[share.index], P) % P
    masked = bytes.fromhex(envelope['masked'])
    return xor_bytes(masked, expand_mask(dh, len(masked)))


def run_malleability_demo() -> dict:
    pub, shares = keygen(16, 11)
    victim = b"SWAP 100 UNITS OF TOKEN_A FOR TOKEN_B"
    original = naive_encrypt(pub, victim)
    delta = b'\x01' + bytes(len(victim)-1)
    changed = copy.deepcopy(original)
    changed['masked'] = xor_bytes(bytes.fromhex(changed['masked']), delta).hex()
    # Committee decrypts CHANGED, included ciphertext. ORIGINAL is excluded.
    disclosed_changed = naive_open(changed, shares[:pub.t])
    attacker_recovers = xor_bytes(disclosed_changed, delta)

    sealed = encrypt(pub, victim, {"sender": "victim", "type": "swap"})
    valid_before = validate_envelope(sealed, pub)
    tampered = copy.deepcopy(sealed)
    bits = bytearray.fromhex(tampered['payload'])
    bits[0] ^= 1
    tampered['payload'] = bits.hex()
    tampered['txid'] = envelope_id(tampered)  # even recomputing identifier won't help
    valid_after = validate_envelope(tampered, pub)
    return {
      "attack": "Related-ciphertext malleability; deliberately naive XOR-mask construction",
      "n": pub.n, "t": pub.t,
      "victim_original_in_finalized_batch": False,
      "attacker_substituted_related_ciphertext": True,
      "naive_attack_recovered_original": attacker_recovers == victim,
      "defended_original_valid": valid_before,
      "defended_related_ciphertext_rejected_before_share_release": not valid_after,
      "defense": "Fiat-Shamir proof of ElGamal randomness bound to full AEAD envelope, enforced prior to share release; AEAD integrity additionally checked at final opening.",
      "caveat": "A reproduction of an attack class, not a formal CCA2 proof and not an attack on current Shutter code."
    }


def run_epoch_leak_demo() -> dict:
    pub, shares = keygen(16, 11)
    included = naive_encrypt(pub, b"PUBLIC TX WILL BE INCLUDED")
    pending_plain = b"SECRET PENDING TX MUST STAY HIDDEN"
    pending = naive_encrypt(pub, pending_plain)
    # Naive epoch scheme releases KEY SHARES rather than per-ciphertext DH shares.
    # Reconstructing the epoch secret makes every ciphertext in the epoch openable.
    coeff = lagrange_at_zero([s.index for s in shares[:pub.t]])
    secret = sum(s.secret * coeff[s.index] for s in shares[:pub.t]) % Q
    u = int(pending['u'],16)
    dh = pow(u, secret, P)
    opened_pending = xor_bytes(bytes.fromhex(pending['masked']), expand_mask(dh, len(pending_plain)))
    # In selective design, per-ciphertext partials for included u do NOT open pending u.
    included_u = int(included['u'],16)
    included_dh = pow(included_u, secret, P)
    falsely_open_pending = xor_bytes(bytes.fromhex(pending['masked']), expand_mask(included_dh, len(pending_plain)))
    return {
        "attack": "Naive epoch-key release reveals excluded pending transactions",
        "excluded_pending_opened_after_epoch_key_release": opened_pending == pending_plain,
        "other_ciphertext_DH_cannot_directly_open_pending": falsely_open_pending != pending_plain,
        "mitigation": "Release verified per-ciphertext DH shares only for finalized batch; no epoch private key release.",
        "caveat": "Selective decryption costs O(nB) communication; this is not optimized batched threshold encryption."
    }


def legacy_unsafe_txid(env: dict) -> str:
    """Replicate the OLD txid hash over raw (including ignored) proof fields.

    Kept only to demonstrate the reported serialization malleability flaw.
    This is not used by the defended protocol.
    """
    return digest(canonical({**envelope_core(env),"rand_proof":env["rand_proof"]}))


def clone_attack_variants(env: dict) -> dict[str, dict]:
    """Three transformations retaining the same mathematical Schnorr proof."""
    clones={}
    upper=copy.deepcopy(env)
    upper['rand_proof']['a']='0X'+upper['rand_proof']['a'][2:]
    upper['txid']=legacy_unsafe_txid(upper)
    clones['uppercase_prefix']=upper
    zeros=copy.deepcopy(env)
    zeros['rand_proof']['z']='0x00'+zeros['rand_proof']['z'][2:]
    zeros['txid']=legacy_unsafe_txid(zeros)
    clones['leading_zeros']=zeros
    extra=copy.deepcopy(env)
    extra['rand_proof']['ignored_junk']='attacker-controlled'
    extra['txid']=legacy_unsafe_txid(extra)
    clones['unknown_proof_field']=extra
    return clones


def run_clone_regression_demo() -> dict:
    """Library-level proof of defense, with distinct txids and identical u."""
    pub,_=keygen(3,2)
    victim=encrypt(pub,b'VICTIM SECRET PENDING TX')
    clones=clone_attack_variants(victim)
    return {
        'victim_valid':validate_envelope(victim,pub),
        'variants':{name:{'different_txid':clone['txid']!=victim['txid'],
                          'identical_u':clone['u']==victim['u'],
                          'defended_validator_rejected':not validate_envelope(clone,pub)}
                    for name,clone in clones.items()},
        'explanation':'Reject malformed proof encodings, extra fields, and replay of same u at mempool admission.'
    }

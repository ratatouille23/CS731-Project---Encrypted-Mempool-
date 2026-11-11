# ShieldedMempool v2 — protocol specification

## 1. Participants and threat model

- **Client** generates valid encrypted transaction locally.
- **Gateway/mempool** validates public envelope and stores pending transaction in SQLite.
- **Coordinator** selects a batch order, asks committee to vote, verifies finality votes, asks for shares and reconstructs plaintext after finality.
- **Committee** consists of n=16 independent processes, with threshold t=11. Each possesses one Shamir key share and one Ed25519 signing key.
- **Adversary** may view visible metadata, alter unprotected ciphertexts in a vulnerable variant, attempt to submit invalid shares, withhold responses or take up to five committee processes offline. Collusion by 11 or more committee members is outside the confidentiality guarantee.

## 2. Honest-mode setup

Let p be the 2048-bit RFC 3526 group 14 modulus, q=(p-1)/2 prime, and g=4 generating the order-q quadratic-residue subgroup. Pick `s,a1,...,a_(t-1) in Zq` uniformly and define `f(X)=s+sum a_j X^j`. Private share for committee i is `s_i=f(i)`; publish `Y=g^s` and Feldman commitments `C_j=g^(a_j)`. Verify `g^(s_i)=prod C_j^(i^j)`.

**Setup trust:** a dealer sees the full key. The shared keystore is encrypted at rest for local development only.

## 3. Client encryption

For each plaintext bytestring M:

1. Sample r uniformly in Zq\{0}.
2. u=g^r and Z=Y^r.
3. K=HKDF-SHA256(Z, salt/domain, u).
4. C=AES-256-GCM(K, nonce, len(M)||M||random_padding, associated_data(version,u,metadata)).
5. Prove knowledge of r via non-interactive Schnorr: a=g^w, c=H(domain,u,a,entire_ciphertext_core), z=w+cr mod q. Include `(a,z)` in the envelope.
6. Define txid=SHA256(canonical_json(envelope_without_txid)).

Public validation checks subgroup membership, length bounds, version, content address and `g^z = a * u^c mod p` **before any share release**. This checks the particular malleability counterexample used in the tests but does not constitute a published CCA security proof.

## 4. Block ordering and simulated finality

A proposal body is `(height, parent_hash, ordered_ciphertexts)` and its hash is SHA256(canonical_json(body)). A committee member validates every included envelope and signs a domain-separated statement containing the height, parent and block hash. Honest nodes remember the first proposal at each height and refuse conflicting proposals.

The coordinator collects at least 11 **distinct and valid** Ed25519 signatures. This *models* an irreversible ordering decision. It does not implement BFT consensus or synchrony-based liveness guarantees.

## 5. Finality-gated share release

Each member checks the same ordered block and certificate, then derives `d_i=u^(s_i)` for each included ciphertext. To prove correctness, it generates a Chaum–Pedersen proof that `log_g(v_i)=log_u(d_i)`, where `v_i=g^(s_i)`. With random w, publish `A=g^w,B=u^w,z=w+c*s_i`; challenge c includes `(block_hash, txid,index,g,v_i,u,d_i,A,B)`. Verify both `g^z=A*v_i^c` and `u^z=B*d_i^c`.

Once 11 valid and unique shares are collected, compute `lambda_i=prod_{j != i} (-j)/(i-j)` modulo q, then `Z=prod_i d_i^(lambda_i)` modulo p. This equals `u^s`. Re-derive K via HKDF, authenticate and decrypt AES-GCM. The secure system never publishes underlying Shamir secret shares.

## 6. Queue transitions and replay assumptions

`pending` → (certified block) → `finalized_unopened` → (successful decryption) → `included`.

Not selected → remains `pending` across blocks. Duplicated txids are rejected by SQLite, and block contents require distinct txids. The finality certificate is the critical transition: if threshold release fails afterward, the block does not become unfinalized and transactions must not return to pending. The current research prototype records this state but does not automatically resume decrypting partially opened blocks after restart.

## 7. Measured critical path

`T_client`, `T_order`, `T_release_rpc`, `T_verify`, and `T_open` are recorded separately, with `T_block = T_order + T_release_rpc + T_verify + T_open` plus scheduling/serialization/queue overhead. `T_postfinality = T_release_rpc + T_verify + T_open`. Plaintext mode uses the same committee ordering simulator as its control, and the measured additional block cost is `T_block_encrypted - T_block_plaintext`.

The live **per-transaction** threshold protocol requires O(nB) share elements, even though node RPC sends a batch-shaped JSON message. See `btx_algebra.py` for an algebra-only BTE example with O(n) shares and an explicit insecurity disclosure.

## 8. Network attack sequence

**Naive malleability:** Victim submits C=(u,masked). Attacker copies u and flips masked ciphertext by a known XOR delta. The attacker's transaction is included first; the original victim remains pending. Decryption of modified message M' reveals original M=M' XOR delta. This is done by real 16-node vote/share services with the deliberately vulnerable `allow_naive=True` mode.

**Naive epoch key release:** In vulnerable mode, nodes release `s_i` for one finalized batch. The attacker interpolates `s=f(0)` and uses it to decrypt any still-pending ciphertext to the same key. Honest mode rejects epoch-key-release requests outright.

**Defended test:** Before a proposal is signed or any share sent, the gateway and nodes reject a modified authenticated envelope that lacks a valid randomness proof. A different valid transaction is finalized, while the victim remains queued. These are empirical test properties, not a security reduction proof.

## 9. Published sources

- F3B (AFT 2023): https://doi.org/10.4230/LIPIcs.AFT.2023.3
- USENIX Security 2024 attack taxonomy and BTE: https://www.usenix.org/conference/usenixsecurity24/presentation/choudhuri
- BEAT-MEV (USENIX Security 2025): https://www.usenix.org/conference/usenixsecurity25/presentation/bormet
- Economic considerations: https://arxiv.org/abs/2307.10878

# ShieldedMempool v2 — Complete Component Guide (math, code, attacks, experiments)

**A function-level guide to the implementation, its underlying mathematics, the threat model, execution flow, experiments, outputs, and limitations.**

## 0. What exactly was built?

This repository delivers a **research-only, local, multiprocess prototype with a real SQLite pending queue and external TCP gateway**. A transaction sender encrypts a JSON payload under a public key, submits it to the queue, and the coordinator chooses an ordering. Committee processes sign that ordering. After the coordinator obtains a threshold finality certificate, the committee releases valid ciphertext-specific decryption shares. The coordinator checks the mathematical correctness of those shares and reconstructs the plaintext payload.

- 16 separately running committee **OS processes** (not a single loop pretending to be independent nodes).
- Threshold 11-of-16, with other `n,t` values supported via `Cluster(n=...,t=...)`.
- A real TCP request/response flow on loopback, with JSON-encoded messages; a separate external client can submit, query status and request blocks.
- Research experiments: two failure demonstrations, timed plaintext-vs-encrypted blocks, node faults, and a synthetic RPC privacy-linkage study.

**What it is not:** actual BFT consensus, a real public blockchain or smart-contract executor, a DKG implementation, a production CCA2-secure threshold PKE, or an optimized pairing-based BTE scheme. `B` independent ciphertexts result in about `n*B` partial decryptions, not `n` batch shares.

## 1. High-level transaction flow

```text
USER / CLIENT
   | JSON transaction
   | encrypt(public_key, transaction, visible_metadata)
   |  - ephemeral group element u = g^r
   |  - AES-GCM payload and nonce
   |  - proof of knowledge of r, bound to ciphertext contents
   v
ENCRYPTED MEMPOOL / ORDERING COORDINATOR
   | immutable ordered block with block_hash
   +-------------- PROPOSE -----------------------+
   |                                              |
   v                                              v
16 COMMITTEE PROCESS SOCKETS (1..16)       (all verify ciphertext)
   | accept first proposal for each height          |
   | vote with Ed25519 signature                     |
   +------------------ VOTES -----------------------+
   |
   v
ORDERER assembles >=11 valid votes into finality certificate
   |
   +-------------- RELEASE(block, certificate) -----+
   |                                                |
   v                                                v
COMMITTEE NODE                                  COMMITTEE NODE
 verify certificate -> compute d_i=u^(s_i)      ...
 produce DLEQ proof bound to block_hash and txid
   |                                                |
   +------------ 11+ verified partial shares -------+
   |
   v
COORDINATOR verifies each proof, reconstructs DH secret
   |  - Lagrange combine
   |  - HKDF --> AES-GCM key
   |  - open authenticated payload
   v
RECOVERED TRANSACTION JSON; measured per-stage timings
```

The system separates the *ordering* phase from the *reveal* phase. Honest nodes only release decryption shares for the exact block they signed, and only when they see a correct threshold certificate for it.

## 2. Mathematical foundation and precise assumptions

### 2.1 Group parameters

File: `shielded_mempool/crypto.py`

- Prime `P` is the **2048-bit RFC 3526 MODP group 14** modulus.
- `Q=(P-1)/2` is its prime-order subgroup size.
- `G=4` lies in the order-`Q` quadratic-residue subgroup.
- All secret exponents are sampled modulo `Q` with `secrets.randbelow`.
- `member(x)` checks range and subgroup membership (`x^Q mod P = 1`).

The modulus is a standard fixed parameter, not newly generated during runtime. Arithmetic uses Python big integers and therefore is not a side-channel-hardened implementation.

### 2.2 Dealer-assisted Shamir key generation

Function: `keygen(n,t) -> (PublicKey, list[Share])`

A trusted dealer chooses secret `s` and polynomial:

`f(X)=s + a1*X + ... + a_(t-1)*X^(t-1) (mod Q)`.

Participant `i` gets secret share `s_i=f(i) (mod Q)`.

The joint public key is `Y=G^s (mod P)`. Feldman commitments `C_j=G^(a_j)` allow checks without disclosing the shares:

`G^(s_i) ?= product(C_j^(i^j)) (mod P)`.

- `Share(index,secret)` carries one secret scalar per node.
- `PublicKey(y, commitments, n, t)` carries public verification material.
- `verify_key_share` checks key-share consistency.
- `PublicKey.share_public(index)` computes `v_i=G^(s_i)` from Feldman commitments; memoized because many ciphertexts reuse the same public share.

**Important:** The dealer knows `s` and generates the shares. This is NOT distributed key generation. A system eliminating the trusted dealer would need a genuine DKG protocol.

### 2.3 Threshold hybrid encryption

Function: `encrypt(pub, plaintext, metadata, pad_to=0)`.

For every transaction independently:

1. Sample fresh random `r` modulo `Q`.
2. Compute ephemeral KEM element `u=G^r`.
3. Compute shared Diffie–Hellman element `Z=Y^r`.
4. Derive AES key `K=HKDF-SHA256(Z, domain, u)`.
5. Encode plaintext as `[4-byte length][plaintext][optional random padding]`.
6. Encrypt with `AES-256-GCM(K, nonce, plaintext, associated_data)`.
7. Generate a Fiat–Shamir Schnorr proof of knowledge of `r`, binding **the complete ciphertext core**.
8. Compute content-addressed `txid` over the resulting authenticated envelope, including the proof.

`metadata` is observable. In the benchmark it contains `sender` and `fee_class`. AES-GCM associated data includes the version, KEM element and metadata.

**Why AES-GCM?** It detects modified payloads when opened. **Why a public randomness proof as well?** Without pre-decryption validation, an attacker can submit a modified ciphertext with the *same* `u` as a pending original, harvest its per-ciphertext ElGamal shares, and decrypt the original even if the modified ciphertext later fails its AEAD tag check. Therefore proof checking must happen before threshold shares are released.

### 2.4 Ciphertext randomness proof

Functions: `encrypt`, `validate_envelope`.

Encryptor knows `r` such that `u=G^r`. Choose random `w`, compute:

`a=G^w`, `c=H("encrypt-randomness-proof-v1",u,a,entire_ciphertext_core) mod Q`, `z=w+c*r mod Q`.

Anyone verifies:

`G^z == a*u^c (mod P)`.

If a malicious forwarder modifies any component of the ciphertext core, the challenge changes. Without knowing `r`, the forwarder cannot generate the corresponding valid proof under the proof's hardness assumptions. A duplicated *identical* envelope has the same `txid` and cannot be included twice within one block.

This is an **educational** proof-binding mechanism tested against a specific related-ciphertext attack. It is not presented as an IND-CCA2 or adaptive-UC proof.

### 2.5 Partial decryption and verifiable DLEQ

Function: `partial_decrypt(pub,share,env,block_hash)`.

Committee member `i` computes a ciphertext-specific partial DH key:

`d_i = u^(s_i) (mod P)`.

The validator's public share is `v_i=G^(s_i)`. The node proves it used the **same secret exponent** in both relations without revealing the exponent. It chooses `w` and publishes:

- `a=G^w`
- `b=u^w`
- `c=H(domain,G,v_i,u,d_i,a,b,block_hash,txid,index)`
- `z=w+c*s_i (mod Q)`

Check in `verify_partial(...)`:

`G^z == a*v_i^c (mod P)` and `u^z == b*d_i^c (mod P)`.

The binding to `block_hash` and `txid` prevents a proof from being silently replayed as authorization for a different block or ciphertext. A malicious node can send a bad share, but the coordinator discards its response.

### 2.6 Lagrange share combination

Functions: `lagrange_at_zero`, `combine_shared`, `decrypt_with_shared`.

For any valid set `S` of `t` distinct nodes, calculate weights:

`lambda_i = product_{j in S,j != i} (-j)/(i-j) mod Q`.

Then recover the shared element:

`Z = product_{i in S} (d_i)^(lambda_i) (mod P)`.

Because `sum(lambda_i*s_i) = s mod Q`, this equals `u^s = (G^r)^s = (G^s)^r = Y^r`.

The AES key can now be reproduced using HKDF and the ciphertext can be authenticated and decrypted. No plaintext or private share must be sent between nodes.

`combine_shared(..., preverified=True)` is an **internal optimization for the coordinator** after it has individually validated the same parts in `engine.py`; external callers must keep the default (`False`) so proofs are always verified.

## 3. Block finality simulation

File: `shielded_mempool/protocol.py`.

Functions:

- `build_block(height,parent_hash,transactions)` produces a deterministic JSON block and SHA-256 hash.
- `validate_tx` verifies public encrypted-envelope proofs, content IDs and fields; plaintext blocks are recognized for benchmarking.
- `validate_block` checks order commitment integrity, unique transaction IDs and basic structure.
- `vote_message` constructs a domain-separated signature payload with block height, parent and hash.
- `verify_certificate` checks at least `t` **distinct** Ed25519 signatures from the original validator registry.

**Voting rule:** A committee node will not sign two different proposals with the same height. This is a useful model of locked ordering and threshold finality but NOT a complete consensus protocol. There is no Byzantine leader rotation, fork recovery, persistence or formal safety/liveness proof. With 11/16 signatures, two certificates must share at least 6 signers. The code assumes honest signers refuse conflicting proposals.

## 4. Independent network nodes and share-release gate

Files: `shielded_mempool/node.py`, `shielded_mempool/cluster.py`.

`Cluster` creates `(public key, secret shares)` and independent Ed25519 signing keys, allocates TCP ports, and spawns a separate Python OS process for each online node. The 16 nodes listen on `127.0.0.1:<assigned_port>`.

`CommitteeNode.handle(request)` implements three request types:

1. `health` — checks that a real service is listening.
2. `propose` — validates block and encryption proofs, records the first proposal per height, and returns an Ed25519 vote.
3. `release` — requires a matching already-attested block **and** a correct quorum finality certificate; only then computes per-ciphertext shares with DLEQ proofs.

`Behavior` injects failures:

- `response_delay_ms`: delays each proposal or release response, simulating network/availability latency.
- `withhold`: declines to return shares after finality.
- `corrupt_share`: deliberately changes the share proof, ensuring the coordinator rejects it.
- `offline`: process is not spawned and its RPC is not contacted.

All network requests are JSON lines. `rpc(...)` reports both request and response payload length, enabling application-layer communication measurement. The TCP transport is *not* encrypted, and process keys are ephemeral with no persistence.

## 5. Coordinator, execution and end-to-end measurements

File: `shielded_mempool/engine.py`.

Main class: `Coordinator`.

`run_block(batch_size, plain=False, pad_to=0)`:

1. **Builds** `batch_size` distinct test JSON transactions.
2. **Encrypts** them using the threshold public key or inserts them as plaintext test transactions.
3. **Builds ordered block** with unique digest and height/parent commitment.
4. **Broadcasts proposal** to active nodes and validates at least 11 returned Ed25519 signatures.
5. **Broadcasts release request** containing the original finalized block and valid certificate.
6. **Checks DLEQ proofs** and discards all of a node's parts if any proof is bad.
7. **Selects 11 validated shares per ciphertext** and reconstructs the DH key with Lagrange interpolation.
8. **Decrypts and authenticates** the AES-GCM payload.
9. **Checks output bytes equal client input bytes**, updates chain height and returns a JSON metric row.

`benchmark_once(cluster, batch_sizes, repeats, pad_to=0)` executes one plaintext baseline and one encrypted block for each repetition and records their latency difference.

**Recorded timings:**

| Field | Measurement |
|---|---|
| `client_encrypt_ms` | Sequential transaction creation and encryption |
| `order_finalize_ms` | Multicast proposal, remote validation and votes, certificate checks |
| `committee_release_rpc_ms` | Multicast finality certificate, remote share calculations and replies |
| `verify_shares_ms` | Local verification until 11 valid responses are obtained |
| `combine_aead_ms` | Share combination, HKDF, AES-GCM recovery and message integrity check |
| `post_finality_ms` | Sum of release, verification and combination: critical post-order path |
| `total_ms` | Whole operation starting from client serialization/encryption |
| `total_added_over_plain_ms` | Encrypted block total minus plaintext baseline total |
| `measured_bytes_sent/received` | Sum of encoded RPC application message bytes |
| `invalid_share_nodes` | Count of encountered invalid-node proof batches |

All stage durations use monotonic `time.perf_counter()` at the coordinator, avoiding clocks synchronized across processes. This is a *sequential, single-coordinator* and localhost experiment, with no attempt to estimate public-internet blockchain confirmation times.

**Interpretation:** `post_finality_ms` is the most meaningful estimate of the incremental decryption critical path within the simplified protocol. `total_added_over_plain_ms` also includes additional public proof validation and encrypted-message serialization. The two answers should not be conflated.

## 6. Attack demonstration A: related-ciphertext malleability

File: `shielded_mempool/attacks.py`.

`run_malleability_demo()` recreates the known *class* of attack described by Choudhuri et al. against a deliberately vulnerable unauthenticated XOR-masked ElGamal scheme.

- Victim's **original ciphertext remains excluded** from the block.
- A malicious relay replaces its masked ciphertext body `C2` with `C2 XOR delta`, retaining `u`.
- The **related ciphertext** is included in an ordered batch and gets threshold-decrypted.
- Decryption yields `M XOR delta`; attacker knows `delta` and recovers `M`.

**Defended variant:** The same alteration is made to an AES-GCM ciphertext; the adversary even updates its `txid`. `validate_envelope` rejects the related ciphertext because the retained Schnorr proof is no longer valid for the entire changed envelope. A correctly behaving node will not emit a DH share for it.

This is not an exploitation of a live service or proof that all chosen-ciphertext attacks are impossible; it only reproduces the known failure mode and the particular defense mechanism in this prototype.

## 7. Attack demonstration B: naive epoch-key privacy leak

File: `shielded_mempool/attacks.py`.

`run_epoch_leak_demo()` compares two reveal policies:

- **Bad:** For an epoch, committee shares reconstruct the *master epoch secret* `s`; the attacker can open an encrypted transaction which never made it into the block.
- **Selective:** For each finalized ciphertext `u_i`, nodes release only `u_i^(s_j)`; opening one included transaction does not directly reveal a different pending transaction with an unrelated `u`.

The selected reveal policy preserves the intended property in this simplified model under a below-threshold collusion assumption. **Cost:** a partial release per ciphertext per node, O(nB). This is exactly why the modern BTE papers introduce more advanced batch aggregation.

## 8. Privacy study: preflight plaintext-RPC information leakage

File: `shielded_mempool/privacy.py`.

In many wallet flows, a transaction is prepared or simulated before final submission. An adversary who observes the plaintext **simulation** and the later encrypted **submission** may infer which transaction was encrypted by linking:

- Sender identity or pseudonym.
- Fee class.
- Ciphertext length (which can reveal original message length).
- Delay from simulation to submission.

The experiment creates deterministic synthetic trace pairs with a random seed, 12 sender identifiers, three fee classes, randomized message sizes and submission times. The attacker gets observable records from the simulation side and encrypted submission side and greedily assigns pairs using sender, fee, size and timing penalties.

Policies:

| Policy | Description | What it tests |
|---|---|---|
| `direct` | Exposed simulation records; no defensive delay or size padding | Baseline linking accuracy |
| `fixed_padding` | Size rounded up to 512-byte bucket | Whether length privacy alone helps |
| `padding_jitter` | 512-byte buckets plus 0–750 ms randomized release delay | Joint size/time cost |
| `adaptive` | Experimental heuristic of padding plus 0–550 ms randomized delay | Intermediate cost, **not proven optimal** |
| `split_provider` | Simulation data hidden from this observer by noncolluding provider assumption | Threat model where candidate plaintexts are unavailable |

- Output `linked_fraction` = fraction of submissions matched to the correct simulation ID.
- Output `mean_added_delay_ms` = extra delay relative to the synthetic nominal submission time.
- Output `mean_padding_bytes` = average extra encoded payload bytes.
- `split_provider` deliberately reports **null linkage accuracy**, not an artificial zero, because this attacker has no simulation candidates to link; real privacy depends on providers' non-collusion.

The matching attacker is a transparent greedy baseline, *not* a state-of-the-art traffic analysis model. Data are synthetic, so conclusions cannot be projected to Ethereum/Aptos without new trace data and a revised experiment. In particular, always-visible, unique metadata can defeat timing/padding defenses.

## 9. CLI and experiment output

File: `shielded_mempool/cli.py`, entrypoint `shielded_mempool/__main__.py`.

```bash
python -m shielded_mempool demo --out results
python -m shielded_mempool attack --out results
python -m shielded_mempool benchmark --sizes 1 2 4 --repeat 1 --out results
python -m shielded_mempool faults --out results
python -m shielded_mempool privacy --privacy-samples 160 --seed 42 --out results
python scripts/plot_results.py results
```

The CLI generates result files automatically, without editing code. It supports `--delay-ms` for injected response delay and `--repeat` for repeated samples. The hardened CLI now computes sample p50/p95/p99 and mean automatically into `benchmark_summary.csv/json`, includes a `--warmup` flag, and generates a stacked critical-path chart and CPU-vs-wall graph. For a statistically meaningful empirical study, run at least 20 measured repetitions per batch size and report hardware limits.

`plot_results.py` produces:

- `results/plots/latency_vs_batch.png`
- `results/plots/latency_breakdown.png`
- `results/plots/privacy_linkage.png`

Charts are made **only** from measured/simulated data already saved in the output folder. They do not insert results from papers or made-up measurements.

## 10. Tests and what they establish

File: `tests/test_crypto.py`

- Group has the expected size and generator belongs to the correct subgroup.
- Every dealer share passes Feldman checking.
- Eleven partial decryptions correctly reconstruct the original plaintext.
- Ten shares are rejected as insufficient.
- Tampered DLEQ share is rejected.
- Proof from one block context cannot be replayed in a different block context.
- Modified ciphertext fails public validation.
- Naive malleability and epoch-key leakage demonstrations reproduce the described outcomes.

File: `tests/test_network.py` — marked `integration`; excluded from the default pytest run on resource-constrained systems.

- Runs real subprocesses, not only isolated mocked objects.
- A node refuses premature release, including when it has already voted but there is no valid certificate.
- A finalized block is decrypted by a 16-node committee.
- Two bad proof-producing nodes are detected while an 11-node honest quorum can still recover the message.
- Six offline nodes prevent 11-of-16 finality quorum formation.

File: `tests/test_privacy.py`

- Experiment rows are created for all policies; output deterministic for fixed random seed.
- Padding adds bytes; randomized timing adds latency; split-provider accuracy remains undefined when simulations are invisible.

## 11. How to modify or extend the prototype

### Change threshold size

In Python:

```python
with Cluster(n=16,t=11) as committee:
    ...
```

Increasing `t` improves protection against colluding decryptors but reduces availability. Increasing `n` increases redundant possible decryptors and baseline network traffic.

### Increase batch size

```bash
python -m shielded_mempool benchmark --sizes 4 8 16 --repeat 2
```

Computational work grows with ciphertext count. The Python reference implementation can take substantial time for B=128 or higher; `B=512` is supported structurally, but not an efficient demonstration. Use small sizes to verify basic functionality first.

### Add a new attack

Add a function to `attacks.py` returning a dict with explicit fields for `success`, `defended`, `assumption` and `limitation`, then add a unit test and CLI hook. Defenses should reject before share release where ciphertext-key reuse is a concern.

### Add a new privacy policy

In `privacy.py`, edit `simulate` to assign an encrypted size and submission time. Update `link_attack` to model what the attacker knows about the policy and metrics. Do not change policies without documenting the adversary's observation assumptions.

### Replace core cryptography with true BTE (future work)

Replace `partial_decrypt` / `combine_shared` with selected *published* BTE algorithms. Retain the certificate gate, network services, metrics and attack tests. Implement setup costs, per-batch share release, and decryption accordingly; use pairing-friendly curves and optimized group arithmetic, with correct assumptions. **Do not simply return a shared epoch private key** to obtain O(n) communication: that breaks excluded-pending privacy.

## 12. Reproducibility and publication constraints

- Crypto keys, proof randomness and OS scheduling are intentionally nondeterministic; performance measurements vary.
- The privacy dataset can be reproduced with `--seed`.
- Store hardware model, CPU core count, OS, runtime Python and dependency versions in your eventual report.
- Run many repetitions under comparable load, and consider confidence intervals.
- Never interpret reported runtimes as matching the 2024 USENIX, BEAT-MEV, BTX or Simple BTE benchmarks; they use different algorithms, languages and hardware.
- Strictly distinguish the published attack from any new claimed vulnerability or security proof.
- A formal paper-quality contribution would require a stronger novel hypothesis, rigorous baselines and/or new cryptographic analysis.

## 13. Reference sources and credit

1. A. R. Choudhuri, S. Garg, J. Piet, and G.-V. Policharla. **Mempool Privacy via Batched Threshold Encryption: Attacks and Defenses**. USENIX Security 2024. *(User-provided `2024-669.pdf`.)*
2. J. Bormet, S. Faust, H. Othman, and Z. Qu. **BEAT-MEV: Epochless Approach to Batched Threshold Encryption for MEV Prevention**. *(User-provided `BEAT-MEV.pdf`.)*
3. A. Rondelet and Q. Kilbourn. **Mempool Privacy: An Economic Perspective**. 2023. *(User-provided PDF.)*
4. A. Agarwal et al. **BTX: Simple and Efficient Batch Threshold Encryption**. *(User-provided PDF.)*
5. G.-V. Policharla. **A Simple Batched Threshold Encryption Scheme**. *(User-provided PDF.)*
6. RFC 3526. **More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange** (prime group 14).

The supplied code implements the standard threshold-ElGamal primitives itself and does not claim any novel cryptographic construction from those works.


---

## 12. v2 source additions: actual persistent pending queue (`mempool.py`)

`Mempool(pub, path=':memory:', allow_naive=False)` owns a SQLite transaction table and ensures **key continuity** using a stored fingerprint of `public_as_json(pub)`. An existing database cannot accidentally be reopened with a different committee key. For restartability, the same encrypted keystore must be loaded.

* `submit(tx, fee_priority=...)` verifies the public Schnorr-style ciphertext proof using `validate_tx`, rejects duplicate content-addressed IDs, checks payload size/capacity, then inserts a `pending` record. It does not decrypt the payload and does not trust any payload assertions.
* `pending(limit,policy)` selects only still-pending records, preserving FIFO or sorting by declared priority. **Important limitation:** the priority is not cryptographically tied to payment or gas; it is a demonstration of an ordering policy, not a complete economic fee mechanism.
* `mark_finalized(txids,height,hash)` atomically transitions the selected records to `finalized_unopened` and stores the certified block head after valid finality. This ensures a transaction cannot simply be reordered into another block when decryption fails.
* `mark_opened(txids,hash)` moves the same certified records to `included` after successful threshold opening. Excluded ciphertexts stay in `pending`.
* `stats`, `status`, and `block_head` support dashboards, recovery checks and restartable height tracking.

**Queue state machine:**

```text
Client ciphertext --> public proof check --invalid--> reject
                           |
                         valid
                           v
                    PENDING in SQLite
                           |
       order selection + 11 certified votes
                           v
                   FINALIZED_UNOPENED
                           |
                  11 valid DH shares
                           v
                        INCLUDED
```

A finalized block cannot safely return to `PENDING` if decryption temporarily lacks a quorum: that would permit it to be ordered a second time. **Hardened v3** persists the exact block body and certificate and implements `recover_unopened()`; on the next `mine` call it retrieves the same threshold shares without changing the ordering. This works across coordinator/process restart provided the same committee key is restored, but it is not a Byzantine consensus/reconfiguration protocol.

## 13. Public TCP gateway (`gateway.py`) and external client

The gateway runs in the coordinator process but exposes a separate local TCP listener. Clients ask for the public committee key and encrypt **locally**; the gateway receives an encrypted envelope. Protocol operations:

| RPC | Request | Response | Confidentiality timing |
|---|---|---|---|
| `info` | `{ "op": "info" }` | committee public key, head and counts | Public only |
| `submit` | envelope + declared priority | ciphertext txid, pending status | No plaintext |
| `pending` | limit + order policy | public pending identifiers | No plaintext |
| `status` | txid | pending/finalized/included | No plaintext |
| `mine` | limit + order policy | finalized block timings and opened payloads | Plaintext only after certification/share reconstruction |

`Gateway.request('mine')` uses an `asyncio.Lock` to avoid two mining RPCs racing at the same chain height. The network uses newline-delimited JSON and binds to loopback for educational safety. To test with independent terminals, see the README commands for `serve` and `scripts/gateway_client.py`.

## 14. Integrated network attack (`network_attacks.py` and `insecure.py`)

The **vulnerable and defended experiments both communicate with actual committee TCP processes**. `run_network_attacks()` starts a fresh 16-node vulnerable committee and then a separate 16-node defended committee. These are independent setups, not purported production attacks on any deployed blockchain.

### 14.1 Naive ciphertext malleability (USENIX 2024 attack class)

In the vulnerable `insecure.py` design, the transaction is:

\[ C=(u=g^r,\; v = M \oplus H(Y^r)) \]

The symmetric mask is deterministically expanded from a DH key; there is **no authentication tag or proof bound to the full ciphertext**. For a known mask difference `delta` of matching length, an attacker changes `v' = v XOR delta`, keeps `u` unchanged, and gets a modified ciphertext accepted into a higher-priority finalized block. Its decryption returns `M' = M XOR delta`, so the attacker reconstructs `M = M' XOR delta` even though the victim's **original ciphertext remains pending**.

The malicious version uses `allow_naive=True`; the production-like path **never** enables it. Its protection is implemented by public `validate_envelope()` before vote/share release. The test flips the payload bytes and recomputes the transaction ID, but cannot supply a matching randomness proof. Both the gateway and all honest nodes refuse the modified ciphertext.

### 14.2 Naive epoch-wide key disclosure

A second vulnerable RPC, `epoch_key_release`, publishes the committee **private-key shares** after the first certified block. An adversary combines 11 shares to learn the entire epoch secret and opens *any* ciphertext encrypted to that same public key—including an excluded pending one. This is the pending transaction privacy failure associated with naive epoch-key release.

The secure committee refuses this RPC. It only releases proof-checked, **ciphertext-specific** `u^(s_i)` shares for ciphertexts in its certified block. Because the ciphertext has a different fresh `u` for each transaction, such an included-ciphertext share cannot simply open the pending ciphertext without the committee secret or a full threshold of colluders.

### 14.3 Why these are NOT formal proofs

Both exercises reproduce known *failure mechanisms* under concrete adversarial inputs. The defended test shows the requested malicious transform and raw key release are rejected. It does not prove adaptive chosen-ciphertext security, general non-malleability, or protection against a threshold of committee colluders.

## 15. Batch-threshold encryption algebra demonstration (`btx_algebra.py`)

The earlier research papers use **batch threshold encryption (BTE)** to reduce communication. Ordinary per-ciphertext threshold ElGamal sends approximately `n * B` partial decryptions for a batch of B; BTE aims to send one constant-size share per committee member. The optimized schemes require special assumptions, pairing-group operations and validity proofs beyond this baseline.

To teach the equations without claiming secure cryptography, `btx_algebra.py` represents bilinear group elements by their **exponents** in a field. The construction shares powers of a secret `tau` via independent Shamir polynomials and tests BTX's compact-share identity. For ciphertexts `(r_i, m_i + r_i*tau^(Bmax+1))`, node j emits one aggregate partial:

\[ D_j = \sum_{i=1}^B f_i(j) r_i \pmod q \]

Combining t partials by Lagrange interpolation recovers

\[ \sigma = \sum_{i=1}^B 	au^i r_i \pmod q. \]

For position `i`, derive its mask by pair-like multiplication with the public `tau^(Bmax-i+1)` and subtract known cross-terms indexed by positions `k != i`. This opens all chosen messages algebraically while the number of transmitted partials is `t` instead of `t*B`.

**CRITICAL: It is NOT secure encryption**: the model publishes `r` as a scalar, not as an opaque group element `g^r`, and its `ek` can be multiplied directly. An observer can compute *every plaintext without any shares*. The model contains no BLS12-381 pairing library or NIZK proof. A real BTX/BEAT-MEV implementation still must be separately developed and audited.

`index_collision_demo` models the scheduling problem when an indexed BTE scheme cannot place two ciphertexts with the same index in a single decryptable batch. It demonstrates sub-batching as a possible mitigation at higher communication cost. It is **not** the BEAT-MEV PRF construction itself.

## 16. Password-encrypted developer key continuity (`keystore.py`)

A secure mempool's pending ciphertexts would become permanently undecryptable if the committee public key changed while the SQLite queue was retained. `Cluster(...,keys_path=...,key_password=...)` loads or creates a local trusted-dealer key file, protected at rest by scrypt and AES-256-GCM, and uses the same threshold key shares and Ed25519 identities after restart. A 0600 file permission is requested on Unix.

The central encrypted file contains **all** member private keys, so whoever knows the password and obtains the file controls the entire committee. This is an educational continuity mechanism, not DKG, HSM storage, or a decentralized validator setup. For production, each member would manage its share independently.

## 17. Execution and measurement details (`engine.py`)

- `Coordinator.run_submitted_block(limit, policy)`: chooses records from SQLite, proposes their exact order, verifies 11 votes, commits their status as finalized, collects per-ciphertext decryption proofs, combines shares, and marks records included. Excluded records stay pending.
- `Coordinator.run_block(B, plain=False)`: creates synthetic benchmark transactions and uses the **same TCP committee flow**. Plaintext mode is a measured comparison baseline.
- `benchmark_queue_once`: measures *both* client-side encryption + gateway queue admission and the block's ordering and release critical path. Client encryption is outside the block-proposal latency, and results report both.
- `benchmark_once`: retains v1 synthetic performance comparisons for regression tests.
- Timing metrics: `client_encrypt_ms`, `order_finalize_ms`, `committee_release_rpc_ms`, `verify_shares_ms`, `combine_aead_ms`, `post_finality_ms`, `total_ms`, and serialized bytes of RPC traffic. `node_partial_crypto_p50_ms` summarizes the nodes returning shares.

During a failure after finality, the chain height has already advanced; an unfinished block is recorded as finalized_unopened. This is critical to avoid silently attempting to finalize a *different* order at the same height.

## 18. Economics demo (`mev_sandbox.py`)

`AMM` uses constant-product reserves `x*y=k` with an illustrative 0.3% fee. In the counterexample, a bot buys before a known victim swap, the victim moves the price, and the bot sells. The program reports the victim's reduction in received tokens and the bot's quote-asset profit **before gas/other costs**.

These values are synthetic, not historical losses or estimates for Ethereum. Protecting a transaction's details *until order fixation* blocks this exact **content-dependent strategy** under the model, but does not remove all arbitrage, transaction censorship or information leakage.

## 19. Testing, reproduction and trust boundaries

The `tests/` folder includes independent crypto unit tests, a 16-process end-to-end demo, an integrated network attack, external gateway client requests, queue persistence, an encrypted keystore roundtrip and toy-BTX algebraic equations. To run all available tests:

```bash
python -m pytest -q -m 'not integration'
python -m pytest -q -m integration
```

An attack test's `passed: true` is evidence that the **particular adversarial input** was handled as intended by this implementation; it is not a cryptographic security theorem. Read `SECURITY.md` and `PAPER_MAPPING.md` before making claims about paper fidelity or cryptographic novelty.


## 20. Single-committee fault-injection harness (`fault_harness.py`)

Earlier experiments repeatedly restarted 16 processes for each scenario, which intermittently stalled on the evaluation host. The v2 final harness launches **one actual 16-process committee**, then updates its simulated `Behavior` fields via an authenticated, coordinator-only `test_config` request before each block. A temporarily unreachable node is represented by removing its index from the coordinator's active RPC set, not by terminating the process; this tests network reachability without changing secret shares or public keys. `fault_harness.py` executes healthy, 2 unreachable, 5 unreachable, 3 invalid shares, 3 withholding, 5 delayed and finally 6 unreachable. The last case is deliberately ordered last because its block cannot attain 11 votes and honest signers who received the proposal retain their lock at that height. Timings and outcomes are in `results/v2/faults_same_committee/faults.json`.

The `test_config` RPC uses an unpredictable token passed only to the coordinator and nodes at startup. It exists exclusively for this localhost research harness; exposing it to outsiders would permit Byzantine fault injection and is prohibited.

## Addendum: hardened v3 fixes (November 2026)

The original report above describes the v2 architecture. The following changes supersede portions of the earlier benchmark and recovery descriptions:

1. **Proof parser and txid**: only exact envelope and `rand_proof` fields are accepted; integer encodings must be the unique lowercase canonical `hex()` output. `envelope_id()` hashes the parsed normalized proof values, and the SQLite queue rejects a reused encryption ephemeral `u`. The intentionally vulnerable `naive` path remains exempt so attacks can be reproduced.
2. **Fast quorum**: `_quorum_rpc()` calls `asyncio.wait(FIRST_COMPLETED)` until `t` cryptographically verified responses arrive, then cancels waiting tasks. Missing votes do not invalidate a genuine certified block: a previously non-voting node verifies the finality certificate independently before providing a share.
3. **Recovery**: the database stores proposals before voting and exact finalized blocks and certificates afterwards. Retrying a proposal uses precisely the same bytes and block hash. `recover_unopened()` handles share failure without changing the certified order, including across process restart if the keystore is unchanged.
4. **Cryptographic validation caching**: a node rehashes the supplied body before trusting its validation cache, verifies its long-term secret share at construction, and skips repeated ciphertext and secret-share checks only on a trusted internal path. Safe-prime subgroup membership is checked with a Jacobi symbol.
5. **Measurements**: `post_finality_ms` is the headline decryption latency; `block_critical_path_ms` separates ordering from decryption; the plaintext baseline has no release round; `node_partial_cpu_p50_ms` separates CPU time from contention-induced wall time. Share-proof verification lives within, and is not additionally added to, the release phase. Percentiles require repeated trials.

See **`HARDENING_REPORT.md`** for specific adversarial experiments, executed test results, empirical limitations and a reproducible command list.

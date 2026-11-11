# Relation to existing research and interpretation of novelty

## Project's actual contribution

The supplied deliverable is a **fully runnable and documented baseline** assembled from established research ideas, not a new cryptographic primitive. It adds a measurement harness, separate OS-process committee nodes, reproducible adversarial scenarios, a synthetic metadata/timing linkage model, and comparative experiments.

The **hypothesis** behind the privacy extension is that effective pre-execution confidentiality can be poor even if the cryptography is sound, because an observer can correlate plaintext transaction-simulation records with encrypted submissions using visible metadata, timing and length. This is **not a newly discovered vulnerability**: the Aptos AIP-144 proposal already discusses preflight/RPC simulation disclosure; the broader economic paper discusses intermediary and metadata leakage. This toy experiment demonstrates how to measure the problem; it is **not sufficient evidence for a peer-reviewed novelty claim**.

## Research comparison

| Reference | What it established | What this implementation does differently / does not do |
|---|---|---|
| Choudhuri et al. (USENIX Security 2024) | Formal BTE definition; pending privacy; malleability pitfalls; O(n) communication | Reproduces an attack *class*, builds educational defense; does **not** reimplement their pairing-based BTE or prove adaptive CCA security |
| BEAT-MEV | Epochless BTE; index selection and sub-batching trade-offs | Does **not** implement puncturable PRFs or its index-collision defense |
| BTX | Collision-free, epochless, FFT-accelerated BTE | Does **not** implement BTX FFT/pairing scheme |
| Simple BTE (Policharla) | BTE with O(B log B) decryption, pipelining and helper-aided verification | Does **not** implement that scheme or claim comparable throughput |
| Mempool Privacy: An Economic Perspective | Validator incentives, disclosure delays and leakage | Synthetic attacker model to quantify metadata/timing effects |
| Aptos encrypted-mempool architecture | Production integrated encrypted mempool | Local experimental finality simulator; not a production blockchain |

## Empirical questions the code can answer

- What extra latency does *this* self-implemented per-ciphertext threshold scheme add after order finalization?
- How do block size and simulated network response delay affect per-block latency?
- What happens when up to five of 16 processes are offline, withholding, corrupting shares or slow?
- Does an attacker recover a pending original via malleability of the deliberately naive XOR envelope?
- Does binding a proof of known `r` to the ciphertext prevent the **same** transformation before shares are released?
- How well does a simple attacker link plaintext simulation traces to encrypted submits under metadata and latency observability assumptions?
- What performance cost accompanies padding and randomized delay in this **synthetic** experiment?

## Future extensions required for a cryptography research contribution

1. Implement a published **true batched threshold encryption** construction, ideally BTX or Simple BTE, with clear notation correspondence, correctness tests, and reproducible baseline comparisons.
2. Replace the quorum-signed finality simulator with actual BFT consensus and persistent state replication; specify safety/liveness assumptions.
3. Replace dealer-assisted shares with distributed key generation and committee reconfiguration, then quantify setup and rotation costs.
4. Improve the privacy extension using real, opt-in trace data and realistic attacker models, assess inference and privacy leakage using robust train/test methodology and confidence intervals.
5. Design a clear new mitigation, compare against existing published defenses, and formalize the adversarial assumptions; at present the `adaptive` policy is just a **heuristic**, not a novel proven privacy mechanism.

## Bibliographic basis

- `2024-669.pdf`: *Mempool Privacy via Batched Threshold Encryption: Attacks and Defenses*.
- `BEAT-MEV.pdf`: *BEAT-MEV: Epochless Approach to Batched Threshold Encryption for MEV Prevention*.
- `Mempool Privacy Economic Perspective.pdf`: *Mempool Privacy: An Economic Perspective*.
- `Simple and efficient threshold encryption.pdf`: *BTX: Simple and Efficient Batch Threshold Encryption*.
- `Simple Batched Threshold Encryption Scheme.pdf`: *A Simple Batched Threshold Encryption Scheme*.

These are user-provided references; the prototype is not a faithful implementation of their optimized BTE algorithms.

# ShieldedMempool — Measured Reference Results

**Date:** November 4, 2026

**Platform:** Containerized Linux x86-64, 5 visible vCPUs, Intel Xeon Platinum 8573C, Python 3.13.5.

**Protocol:** 16 independent localhost TCP committee processes, threshold 11; finite-field 2048-bit group; verified partial decryptions and 11-of-16 Ed25519 ordering certificate. Transactions are dummy JSON swaps. No real chain, global-network or optimized BTE.

## 1. Actual block timings

The following data come from actual saved benchmark output. Each batch size is a **single measurement** on the same environment, with B=4 run in a separate deployment. These are representative smoke measurements, **not statistically significant latency estimates**.

| Batch size | Plaintext end-to-end | Threshold encrypted end-to-end | Post-finality decryption path | Encrypted overhead vs plaintext |
|---|---:|---:|---:|---:|
| 1 | 33.8 ms | 3869.0 ms | 3309.7 ms | 3835.2 ms |
| 2 | 24.0 ms | 7938.7 ms | 6899.1 ms | 7914.7 ms |
| 4 | 36.4 ms | 16655.9 ms | 14168.2 ms | 16619.5 ms |

The steep runtime cost is expected: all 16 Python processes perform repeated 2048-bit modular exponentiation and send a separate share/proof per transaction. The coordinator additionally checks many proofs. This is **not** a high-performance cryptographic implementation; papers using optimized Rust/C++ and FFT-based pairing schemes must not be compared to these numbers without qualification.

`results/benchmark.json` and `results/benchmark.csv` record the underlying phases, bytes and individual block IDs. The recorded baseline and encrypted times include key interactions with the finality simulator; the baseline does not need decryption. The experiment checks every recovered payload against original bytes.

## 2. Related-ciphertext and pending epoch disclosure demonstrations

`results/attacks.json` confirms:

- The intentionally **unauthenticated XOR-masked** encryption allows an attacker who substitutes an included related ciphertext to recover an **excluded** victim plaintext.
- The protected envelope's ciphertext-bound randomness proof rejects the same modification before a release.
- A naive **epoch-wide private-key release** exposes a pending, unincluded transaction.
- Releasing ciphertext-specific DH shares instead of an epoch-wide secret does not directly open an unrelated pending ciphertext.

These are demonstrations of published failure classes, not an attack against modern live networks and not a mathematical proof of CCA2 security.

## 3. Synthetic RPC-simulation linkage experiment

The synthetic experiment used 160 test transactions and random seed 42. The observer sees plaintext simulation logs (except in `split_provider`) and encrypted-submission metadata, length and timing.

| Policy | Fraction correctly linked | Mean extra submission delay | Mean extra length |
|---|---:|---:|---:|
| Direct | 100.00% | 5.4 ms | 0 B |
| Fixed 512-byte padding | 98.75% | 5.4 ms | 277.0 B |
| Padding + jitter | 86.88% | 395.2 ms | 270.1 B |
| Adaptive heuristic | 90.00% | 289.6 ms | 270.1 B |
| Split RPC providers | Not defined | 5.4 ms | 0 B |

**Finding under the modeled observer:** padding alone provides little protection when metadata and timing remain visible. Random delay reduces the simple linkage attack's accuracy at meaningful latency cost. The proposed adaptive heuristic does **not** outperform the more costly padding+jitter policy on this data. It should not be reported as a demonstrated privacy improvement. The split-provider experiment intentionally does not score a zero, since the observer has no visible plaintext simulation records under the non-collusion assumption.

This model is entirely synthetic and the attacker is a simple greedy matching algorithm. A stronger attacker, other metadata distributions, or realistic RPC collection can change the results substantially.

## 4. Actual failure-injection outcomes

These results were recorded from **separate 16-process deployments** with `B=4` transactions per block. Each configuration was run once (exploratory smoke result; no statistical inference).

| Scenario | Correctness outcome | End-to-end elapsed | Validated / observed behavior |
|---|---|---:|---|
| Healthy, 16 active | Pass | 19,970.0 ms | Normal quorum success |
| 2 offline, 14 active | Pass | 21,479.1 ms | Enough shares remain |
| 5 offline, 11 active | Pass | 14,682.3 ms | Exactly 11 nodes remain, just sufficient |
| 3 malicious share proofs | Pass | 21,799.4 ms | All 3 invalid share senders rejected; 13 potential honest nodes remain |
| 3 share withholding | Pass | 17,450.1 ms | 13 usable responses remain |
| 6 offline, 10 active | **Expected failure** | 1,426.3 ms | Only 10 finality votes; cannot reach 11-of-16 |
| 5 delayed nodes | Pass | 16,450.5 ms | Injected 250 ms per response for 5 nodes |

The measured times are noisy, since these are independent process starts and only one sample per case. In particular, **do not interpret the 5-offline case being faster than the healthy case as proof that failures improve performance**. It can reflect CPU contention, process scheduling and many other factors. `results/faults.json` and `.csv` contain exact experimental values.

The current CLI defaults to a 1-transaction fault block for quicker re-execution. To reproduce the included B=4 scenarios, use `python -m shielded_mempool faults --fault-batch 4 --out results`.

## 4.1 Test execution

- Default automated unit suite: **5 passed, 3 integration tests deselected**, using `pytest -q tests`.
- Functional 16-node console demos and block benchmarks were run successfully and recorded in JSON.
- The seven 16-node fault scenarios above were executed and recorded.
- Multiprocess pytest cases are opt-in, since repeated process spawning inside a pytest process can be slow or unstable in restricted CI environments; run the standalone CLI for the primary system-level demonstration.

## 5. What to report in a submission

Include actual logs, plots and runtime conditions. Run multiple repetitions to estimate quantiles or confidence intervals; the current smoke tests are too few to justify p95/p99 statistics. Report dealer-assisted setup, limited finality simulation, lack of true BTE aggregation, exposed sender/fee metadata and theoretical limitations of the proof system. The result supports a **functional implementation** claim, not a new cryptographic security or performance theorem.

The complete underlying files can be regenerated from the included CLI; see `README.md` and `COMPONENT_GUIDE.md`.

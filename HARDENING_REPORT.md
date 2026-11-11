# ShieldedMempool v3 — Security and Measurement Hardening Report

## Scope

This is a patch of the original **ShieldedMempool v2** Python research prototype, not a replacement cryptosystem. The active scheme is **dealer-assisted 11-of-16 threshold ElGamal with per-transaction decryption shares**. Communication is still **O(nB)** for n committee processes and B ciphertexts, not the advanced O(n) batched scheme. Ordering finality remains a **quorum-signed simulation**, not a production BFT protocol. This report documents changes in response to an adversarial audit and their measured or tested effects.

## 1. Re-encoded randomness-proof clone bypass — fixed in tested model

**Original issue:** The v2 transaction identifier included the literal JSON representation of the randomness proof, while Schnorr verification interpreted its `a` and `z` fields numerically. An adversary could prepend `0X`, introduce leading zeroes or include ignored fields, producing a different `txid` for identical mathematical ciphertext material and causing a duplicate transaction to be admitted and decrypted while the victim was still pending.

**Changes:** `crypto.py` now refuses unknown fields in the top-level envelope or `rand_proof`, requires canonical `hex(int(s,16)) == s` encodings for `u`, `a`, and `z`, and derives the identifier from decoded-and-normalized mathematical fields. `mempool.py` additionally enforces a **unique `u`** for defended envelopes, across all transaction statuses; `protocol.py` also checks duplicate `u` values within blocks. The deliberately vulnerable `kind='naive'` path is exempt from this defense so the published-class demonstration remains reproducible. Importantly, accepting an arbitrary extra field in the payload would not be safe to use as a unique identifier.

**Tests:** `tests/test_hardening_regressions.py` proves the three clones passed a copy of the old permissive validation but fail the hardened parser, queue admission, and block validation. `network_attacks.py` submits each clone to the actual defended 16-node committee and checks all nodes reject the proposal. Its original XOR-malleability and epoch-release demonstrations still pass.

**Security limit:** This protects the demonstrated encoding/replay bypass. It does **not** establish general IND-CCA2 security; the underlying research construction and NIZK proof conditions require a separate formal analysis.

## 2. Waiting for every committee member — fixed

**Original issue:** `asyncio.gather()` waited for all live processes even when 11 valid responses had already arrived. A few slow peers could inflate block time by seconds.

**Changes:** `Coordinator._quorum_rpc()` uses `asyncio.wait(..., FIRST_COMPLETED)` and accepts responses **only after verifying** Ed25519 votes or all DLEQ shares from that node. It returns at the first threshold of valid responses; pending network tasks are cancelled. Nodes that did not vote can still release shares for a correctly certified block after independently checking the full block and certificate. This prevents a fast voting quorum from excluding otherwise useful decryption nodes.

**Tests:** A 3-of-5 integration regression delays two nodes by 4,000 ms and requires a block to complete in under 3.5 s. The single-committee 16-node fault suite completes the `slow_committee` case without waiting for all delayed peers. The test duration is hardware-specific; the property under test is that no four-second wait is imposed on a healthy quorum.

**Measurement caveat:** Recorded RPC byte counts cover replies **received by the coordinator** before quorum completion; they do not count bytes from peer processes that finish after the client has cancelled the wait.

## 3. Quorum failure locking block height — fixed for the prototype

**Original issue:** A failure with fewer than t votes left voting nodes locked to a particular block hash. Retrying with freshly encrypted ciphertexts created a different hash and triggered `double proposal at height`.

**Changes:** The coordinator caches the identical failed synthetic proposal. For queued blocks, `mempool.py` persists the candidate body in `staged_proposals` before seeking votes, including across a coordinator restart. On retry it reuses precisely the same transaction bytes, order, height and hash instead of re-encrypting or reselecting transactions.

**Tests:** Both synthetic and queued 3-of-5 quorum failure regressions restore a quorum and then certify **the exact originally staged hash**.

## 4. Finalized but unopened transactions — recovery implemented

**Original issue:** Transactions that reached `finalized_unopened` had no pathway to obtain shares after the first attempt failed.

**Changes:** On certification, the SQLite database records the complete finalized block and its signed vote certificate. A failed share round retains them. `Coordinator.recover_unopened()` and the gateway's normal next `mine` call re-request shares for the **same certified block** before proposing anything new. Committees started with the same encrypted keystore can verify that old certificate and release shares after a process restart, even when they did not participate in its original vote.

**Tests:** Recovery after share withholding, new-coordinator recovery, and process-restart recovery with the same key material. No second ordering event occurs during recovery.

**Limit:** Committee signing/voting locks are still in memory, and there is no crash-safe Byzantine consensus or replicated log. The persisted certificate protects this recovery path in the specified trusted coordinator model, not general fork safety.

## 5. Benchmark accuracy and transparency

**Wall time versus CPU:** `node.py` now reports `time.process_time()` as `partial_crypto_cpu_ms` alongside `time.perf_counter()` elapsed time. The coordinator logs per-node median CPU and wall times and CPU quota, affinity, and logical core count. This makes effects of 16 concurrent Python processes observable rather than treating wall time as pure cryptographic computation.

**Critical path:** Plaintext blocks no longer make a meaningless release RPC. The main metric `post_finality_ms` measures the actual encrypted decryption stage after ordering. `block_critical_path_ms` is ordering + decryption. `client_encrypt_ms` and `gateway_encrypt_and_admit_ms` are reported **separately** and excluded from the block critical-path delta. `ordering_extra_ms` captures the additional ordering/validation cost versus plaintext. Share verification is timed explicitly within the release stage, rather than double-counted.

**Avoiding redundant expensive checks:** Each node caches validated blocks by their cryptographic hash and separately recomputes the supplied body digest to prevent cache poisoning. Each node verifies its long-term secret share once at initialization. Once a finalized block has been validated, `partial_decrypt()` accepts a trusted internal fast path that skips repeated ciphertext and key-share verification. Untrusted public calls still run full checks. `member()` now uses a binary Jacobi-symbol test for the order-q subgroup of the fixed safe prime, instead of a full-length modular exponentiation. A test cross-checks it against the original exponentiation rule.

**Repeated trials:** The benchmark command accepts `--repeat`, `--warmup`, and arbitrary `--sizes`, and now generates `benchmark_summary.json/csv` with sample count, median (p50), p95, p99 and mean. It generates `stacked_critical_path.png` and `node_cpu_vs_wall.png`. Rows with fewer than 20 repeats are flagged **exploratory**. Suggested high-effort sweep (could take hours on slow Python machines):

```bash
python -m shielded_mempool benchmark-queue \
  --sizes 1 2 4 8 16 32 64 128 256 --repeat 20 --warmup 2 \
  --out results/full_sweep
```

The archived `results/hardened/bench` is a **smoke benchmark (B=1,2, two measured repeats, one discarded warm-up)**, not publication-quality evidence. Published v2 single-run numbers use the old implementation and should not be pooled with these changes. Absolute MODP Python runtimes should never be compared directly with optimized pairing/elliptic-curve publications.

## 6. Recorded verification

- Non-integration test suite: **13 passed** after patch.
- New focused hardening integration suite: **6 passed**, including quorum speed, same-hash retry, staged queue retry, finalized recovery, forged-cache protection, and process restart with matching keystore.
- Existing 16-node network attack command: **passed** after including the three clone regressions.
- 16-node fault command: healthy, 2 offline, 5 offline, 3 invalid shares, 3 withheld shares, and 5 delayed peers succeeded; 6 offline correctly failed (10 votes), followed by a successful **identical-block** retry.
- Full combined integration suite: experienced intermittent multi-process hangs in this container even though the focused tests and the formerly hanging final test succeeded when run independently. Do not treat it as a clean all-in-one test run.
- Measured smoke benchmark: see `results/hardened/bench` for exact records. It is **not** the requested 20-repeat B=64–256 evaluation.

## 7. Unaddressed research and production requirements

- Still **O(nB)** decryption-share traffic, rather than true BTE `O(n)`.
- Dealer-assisted Shamir sharing rather than robust distributed key generation.
- No authenticated adversarial peer network, consensus algorithm or durable per-node vote log.
- Not a formal cryptographic security proof or an audited production implementation.
- No scientifically strong p95 / throughput extrapolation to 64–256 transactions has been produced in this environment.

The fixes above substantially improve the *educational prototype* and address the concrete reproduced issues. They do not convert it into production blockchain infrastructure.

### Additional explicit 16-node quorum regression

Executed `PYTHONPATH=. python scripts/check_fast_quorum_16.py` with five committee nodes configured to delay each reply by 4 seconds. The 11-of-16 encrypted block completed in **1,005.4 ms**, with 11 verified release bundles (see `results/hardened/fast_11_of_16.json`). This corrects the original all-node-gather latency defect for the tested configuration.

# ShieldedMempool v3 (hardened v2) — 16-node encrypted-mempool research prototype

A reproducible research prototype built from the **existing v1 source**, extending it with a real SQLite pending queue, external client/server API, 16 separate committee processes, post-finality threshold decryption, *in-network* published-class attack demonstrations, fault injection, economics example, and an explanatory BTX batching model.

> **Important scope:** The deployable encrypted-mempool path implements **dealer-assisted Shamir/Feldman + per-ciphertext threshold ElGamal KEM and AES-256-GCM**, with **O(nB)** share communication. It is not a cryptographically secure implementation of the pairing-based **O(n)** BEAT-MEV/BTX BTE primitive. `btx_algebra.py` is an explicitly **insecure symbolic-exponent group model** of BTX math; it trivially reveals plaintext without shares and must never be deployed. The two are deliberately separate.

## Installation

Requirements: Python 3.10+ (tested with Python 3.13), network access is **not required** for the tests once dependencies are present.

```bash
cd ShieldedMempool
python -m pip install -r requirements.txt
python -m pytest -q -m 'not integration'
# Integration suites may stall in constrained environments; run the focused
# regressions or individual subprocess tests if needed:
python -m pytest -q -m integration tests/test_hardening_regressions.py
```

## Demonstrations

```bash
# Baseline end-to-end block on 16 independent TCP node processes (t=11)
python -m shielded_mempool demo --out results/current

# Vulnerable and defended attacks via the ACTUAL 16-node protocol
python -m shielded_mempool attack-network --out results/current

# Prior standalone cryptographic counterexamples
python -m shielded_mempool attack --out results/current

# True mempool queue workload, separate pre-submission encryption measurements
python -m shielded_mempool benchmark-queue --sizes 1 2 4 --repeat 1 --out results/current/queued

# Existing synthetic baseline workload
python -m shielded_mempool benchmark --sizes 1 2 --repeat 1 --out results/current/synthetic

# Algebraic BTX equation demo + BEAT-MEV-style index-collision toy model
python -m shielded_mempool toy-btx --out results/current

# Deterministic, synthetic AMM sandwich example
python -m shielded_mempool mev-demo --out results/current

# Run seven fault types plus same-hash recovery on ONE live committee
python -m shielded_mempool faults --out results/current/faults

# Alternatively run any one mode independently
python -m shielded_mempool faults --fault-only five_offline --out results/current/five_offline
python -m shielded_mempool faults --fault-only three_invalid --out results/current/three_invalid
python -m shielded_mempool faults --fault-only three_withhold --out results/current/three_withhold
python -m shielded_mempool faults --fault-only six_offline_fails --out results/current/six_offline
```

## Live client/server and pending transaction flow

**Terminal A:** Launch 16 TCP-serving committee processes and a local gateway:

```bash
python -m shielded_mempool serve --port 8765
```

**Terminal B:** Submit multiple encrypted transactions **without producing a block**:

```bash
python scripts/gateway_client.py submit --message 'SWAP 12 A for B' --priority 2
python scripts/gateway_client.py submit --message 'SWAP 40 A for B' --priority 5
python scripts/gateway_client.py pending
```

**Terminal B:** Finalize a block of one transaction, check that the other stays pending, then finalize the second:

```bash
python scripts/gateway_client.py mine --limit 1 --policy priority
python scripts/gateway_client.py pending
python scripts/gateway_client.py mine --limit 1
python scripts/gateway_client.py info
```

The gateway provides `info`, `submit`, `pending`, `status`, and `mine` RPC operations as newline-delimited JSON. All gateway and committee TCP listeners bind to `127.0.0.1` by default. Transaction content appears only in the post-finality `mine` result; clients send encrypted envelopes on submission.

## Persistent mempool / key continuity across restarts

An SQLite database is tied to a particular committee public-key fingerprint. Do not keep an encrypted queue while regenerating its committee key. For an **educational local deployment**, use a password-encrypted developer keystore (it contains all secret shares and is NOT distributed key generation):

```bash
export SHIELDED_MEMPOOL_KEYSTORE_PASSWORD='a-long-unique-demonstration-passphrase'
python -m shielded_mempool serve --db results/demo.sqlite --keys results/committee.keys.enc
```

Restart with the same password and the same `--db` and `--keys`. Do **not** commit the `.enc` keystore or passphrase to Git. The proof-of-concept keystore uses scrypt + AES-GCM and writes a mode-0600 file on Unix. Running an in-memory queue (`--db :memory:`) requires no keystore.

## Measured research results

Actual queue-based 16-node results from this environment, single run per batch size:

| B | Block time | Post-finality time | Added over plaintext | 
|---:|---:|---:|---:|
| 1 | 2574.4 ms | 2293.2 ms | 2556.1 ms |
| 2 | 4999.0 ms | 4446.9 ms | 4981.8 ms |
| 4 | 10256.8 ms | 9146.4 ms | 10238.6 ms |

These are **historical v2 results** and should not be pooled with the hardened version. The old plaintext baseline included unnecessary release RPC traffic and the encrypted run waited for every node, so those added-latency values are superseded. See `HARDENING_REPORT.md` and `results/hardened/bench`. The secure path remains unoptimized **2048-bit MODP Python threshold ElGamal**, not modern O(n)-communication BTE.

### Hardened v3 changes and measurement commands

- Reject Schnorr-proof clones with alternate integer encodings or unknown fields, and prevent duplicate defended ciphertext `u` values in the persistent queue.
- Stop collecting votes or partial decryptions after **t verified replies**, without waiting for slow peers.
- Retry an **identical failed proposal**, including from SQLite after coordinator restart, and reopen already-certified `finalized_unopened` blocks.
- Expose per-node CPU time, actual decryption critical path (post-finality), and correct plaintext baseline without an unnecessary share-release stage.
- Support warm-up, repeated benchmark runs, sample p50/p95/p99 statistics, and graphs.

```bash
# Quick local smoke check; low sample counts are not statistically reliable.
python -m shielded_mempool benchmark --sizes 1 2 --repeat 2 --warmup 1 --out results/quick

# Extended repeatable study: much slower on CPU-constrained machines.
python -m shielded_mempool benchmark-queue --sizes 1 2 4 8 16 32 64 128 256 \
  --repeat 20 --warmup 2 --out results/full_sweep

# Defensive serialization/clone test over 16 processes and recovery fault scenario.
python -m shielded_mempool attack-network --out results/attacks
python -m shielded_mempool faults --out results/faults
```

The `benchmark_summary.csv/json` and stacked charts are written alongside `benchmark.json` automatically. Benchmark results with fewer than 20 observations are labeled exploratory. Due to cost, the full 20-repeat 64–256 study has **not** been run in this environment.

## Directory map

| Component | Purpose |
|---|---|
| `shielded_mempool/crypto.py` | Implemented Shamir, Feldman commitments, threshold ElGamal, proofs, AES-GCM |
| `shielded_mempool/mempool.py` | SQLite pending queue, duplicate rejection, priorities, finalized/included states |
| `shielded_mempool/gateway.py` | External client RPC, pre-encrypted submission, status, batch production |
| `shielded_mempool/protocol.py` | Validated ordered blocks, hashes, signed finality certificates |
| `shielded_mempool/node.py` | Individual TCP-serving decryptor/validator process, finality gating |
| `shielded_mempool/cluster.py` | Spawn 16 independent processes, faults, network RPC |
| `shielded_mempool/engine.py` | First-t quorum collection, retry/recovery, queued benchmarks, critical-path instrumentation |
| `shielded_mempool/benchmarking.py` | Percentiles, sample summaries, and charts (CPU vs wall, phase breakdown) |
| `tests/test_hardening_regressions.py` | Exact clone, quorum, recovery, restart and measurement regressions |
| `shielded_mempool/network_attacks.py` | Malleability and epoch-key disclosure via actual committee RPCs |
| `shielded_mempool/insecure.py` | Vulnerable XOR construction used *only* for attacks |
| `shielded_mempool/attacks.py` | Independent reproduction of published failure classes |
| `shielded_mempool/btx_algebra.py` | **Unsafe educational** BTX equations and index collision demonstration |
| `shielded_mempool/mev_sandbox.py` | Standalone deterministic AMM sandwich economics example |
| `shielded_mempool/keystore.py` | Password-encrypted trusted-dealer demo keystore |
| `shielded_mempool/privacy.py` | Synthetic client-simulation/metadata linkage experiment |
| `scripts/gateway_client.py` | External command-line client |
| `tests/` | Unit and actual TCP-process integration tests |

## Documentation

- **`COMPONENT_GUIDE.md`** — detailed component-by-component mathematical and code walkthrough.
- `PROTOCOL_SPEC.md` — encryption/decryption/finality state machine and attack assumptions.
- `PAPER_MAPPING.md` — exact reference-to-implementation correspondence, including gaps.
- **`SECURITY.md`** — threat model, implementation limits and explicit non-claims.
- **`HARDENING_REPORT.md`** — security findings, code changes, adversarial regressions, corrected benchmark definitions and remaining gaps.
- `RESULTS_REPORT_v2.md` — actual experiments, reproducibility and measured numbers.
- `RELEASE_NOTES_v2.md` — precise assignment compliance, additions and remaining gaps.

## Primary references

1. Rondelet and Kilbourn, *Mempool Privacy: An Economic Perspective* (2023), https://arxiv.org/abs/2307.10878
2. Choudhuri et al., *Mempool Privacy via Batched Threshold Encryption: Attacks and Defenses* (USENIX Security 2024), https://www.usenix.org/conference/usenixsecurity24/presentation/choudhuri
3. Bormet et al., *BEAT-MEV: Epochless Approach to Batched Threshold Encryption for MEV Prevention* (USENIX Security 2025), https://www.usenix.org/conference/usenixsecurity25/presentation/bormet
4. Zhang et al., *F3B: A Low-Overhead Blockchain Architecture with Per-Transaction Front-Running Protection* (AFT 2023), https://doi.org/10.4230/LIPIcs.AFT.2023.3
5. Agarwal et al., *BTX: Simple and Efficient Batch Threshold Encryption* (2026), user-supplied paper.

**Research-use only.** This does not include distributed key generation, permissionless fee validation, Byzantine consensus, an authenticated production RPC layer, or a formally proven CCA-secure BTE scheme.

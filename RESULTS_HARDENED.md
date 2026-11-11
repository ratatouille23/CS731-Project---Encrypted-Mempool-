# Hardened v3 — Measured results and test provenance

## Environment

A constrained Linux container with **5 logical CPUs** and an effective **4.0-core cgroup quota**. The committee is 16 separate Python processes with an 11-of-16 threshold using safe-prime MODP 2048-bit arithmetic. These figures are research smoke tests, not target-chain performance predictions.

## Short warmed synthetic benchmark (only 2 measured repetitions per size)

| B | Repetition | Encrypted block critical path | Encrypted post-finality | Node p50 CPU for partial decryption | Node p50 wall for partial decryption |
|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 1,466.8 ms | 1,366.9 ms | 79.8 ms | 311.2 ms |
| 1 | 1 | 1,572.0 ms | 1,463.4 ms | 86.5 ms | 315.8 ms |
| 2 | 0 | 3,007.9 ms | 2,753.5 ms | 152.7 ms | 575.3 ms |
| 2 | 1 | 2,515.8 ms | 2,288.1 ms | 135.4 ms | 481.8 ms |

**Source**: `results/hardened/bench/benchmark.json`, with `--sizes 1 2 --repeat 2 --warmup 1`. The plain baseline did **not** perform a release round. Client encryption is excluded from the `block_critical_path_ms` values.

## Short warmed SQLite queue benchmark (2 measured repetitions at B=1)

| Repetition | Block critical path | Post-finality | Node median CPU | Node median wall |
|---:|---:|---:|---:|---:|
| 0 | 1,538.9 ms | 1,420.9 ms | 74.6 ms | 285.9 ms |
| 1 | 1,444.3 ms | 1,346.8 ms | 70.8 ms | 270.9 ms |

**Source**: `results/hardened/queue_smoke/benchmark.json`. These two samples are **insufficient** for credible p95/p99 estimates. The CLI emits percentiles for transparency but flags sample sizes below 20 as exploratory.

## 16-node network attack regression

`results/hardened/network_attacks.json` confirms that all three mathematical-clone variants were rejected by the defended queue and by every tested committee proposal. The original deliberately vulnerable XOR-malleability demonstration and epoch-wide key disclosure demonstration remained reproducible. None of this constitutes a full formal IND-CCA2 security proof.

## 16-node fault harness and same-hash retry

`results/hardened/faults.json`: healthy, two offline, five offline, three invalid-share nodes, and three withholding nodes completed successfully. Six offline nodes caused the expected 10-of-16 voting failure; restoring all nodes enabled certification of the **exact previously staged block hash**. The subsequent slow-committee scenario also succeeded. Latency figures are workload/environment dependent; inspect the JSON for the exact individual-run values.

## Test execution notes

The hardened v3 non-integration suite completed **14/14 passed**. The focused hardening integration suite completed **6/6 passed**. The original 16-process attacker test and gateway integration succeeded individually. One attempted all-in-one multiprocess integration run stalled in this container after 9 of 10 tests; its final test separately passed. Large-batch and 20-repeat trials were **not completed**.

## How to obtain statistically stronger evidence

```bash
python -m shielded_mempool benchmark-queue \
  --sizes 1 2 4 8 16 32 64 128 256 --repeat 20 --warmup 2 \
  --out results/full_sweep
```

Do not present this command as already run. This may be slow on ordinary hardware because the group operations and proof checks are implemented in Python, and there are 16 independent processes. Always report p50 and p95 with sample count, CPU quota, and percentile estimation convention.

## Exact 11-of-16 fast-quorum stress test

`scripts/check_fast_quorum_16.py` configured **five nodes with 4,000 ms delay** while 11 nodes remained healthy. The measured block completion time was **1,005.4 ms**, with **11 valid share bundles**, post-finality time **854.2 ms**, and per-node median CPU/wall partial-decryption times **76.1/167.8 ms**. This independently demonstrates that the hardened coordinator does not wait for the five slow responders. The machine and workload determine absolute latency. Raw evidence: `results/hardened/fast_11_of_16.json`.

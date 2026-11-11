# Reproduction checklist (ShieldedMempool v2)

## 1. Environment

- Use Python 3.10+ and install `requirements.txt`. The development machine for the measurements was a constrained Linux container; results will vary on other systems.
- Run shell commands from the **ShieldedMempool root**.
- Ensure local TCP binding to `127.0.0.1` is permitted. The default node group allocates ephemeral loopback ports.
- Source code and proof routines are educational, not formally audited.

## 2. Verify implementation

```bash
python -m pytest -q -m 'not integration'
python -m pytest -q -m integration tests/test_gateway_v2.py::test_attacks_through_real_sixteen_processes
python -m pytest -q -m integration tests/test_network.py::test_00_real_sixteen_process_threshold_block
python -m pytest -q -m integration tests/test_gateway_v2.py::test_gateway_actual_client_rpc_with_committee
python -m pytest -q -m integration tests/test_gateway_v2.py::test_keystore_and_pending_queue_survive_restart
```

On heavily resource-constrained systems, **run each integration test in a fresh Python process**. Repeated multiprocess startup in one long-lived runner intermittently stalled during this evaluation. The individual test invocations completed successfully.

## 3. Produce live results

```bash
python -m shielded_mempool attack-network --out results/new_attack
python -m shielded_mempool benchmark-queue --sizes 1 2 4 --repeat 1 --out results/new_queue
python scripts/plot_v2.py --input results/new_queue/benchmark.json --out results/new_queue/plots
python -m shielded_mempool toy-btx --out results/new_toy
python -m shielded_mempool mev-demo --out results/new_mev
```

The new fault harness is now capable of reusing the **same 16 live node processes** and changing injected faults between blocks:

```bash
python -m shielded_mempool faults --out results/new_faults
```

If you want individual standalone runs, invoke each scenario separately:


```bash
python -m shielded_mempool faults --fault-only healthy --out results/fault_healthy
python -m shielded_mempool faults --fault-only two_offline --out results/fault_two
python -m shielded_mempool faults --fault-only five_offline --out results/fault_five
python -m shielded_mempool faults --fault-only three_invalid --out results/fault_invalid
python -m shielded_mempool faults --fault-only three_withhold --out results/fault_withhold
python -m shielded_mempool faults --fault-only six_offline_fails --out results/fault_six
python -m shielded_mempool faults --fault-only slow_committee --out results/fault_slow
```

Each `faults.json` is scoped to one trial. A single observed failure of an all-at-once runner is an instrumentation/runtime limitation, not evidence that an encryption scheme withstands arbitrary failure scheduling.

## 4. Understand results

- `results/v2/network_attacks.json`: saved 16-node adversarial demonstration.
- `results/v2/queue_benchmark/benchmark.json`: measured one-run-per-B queue benchmark, B=1,2,4.
- `results/v2/faults_same_committee/faults.json`: seven scenarios using a single 16-node committee. `results/v2/fault_suite_individual_runs.json` retains prior individually tested cases.
- `results/v2/toy_btx.json`: algebraic batching only, **insecure model**.
- `results/v2/mev_sandbox.json`: synthetic AMM example.
- `results/v2/plots`: empirical latency and breakdown graphs.

All timings are single-run unless the command is repeated; statistical claims require controlled hardware and repetitions. `RESULTS_REPORT_v2.md` identifies all known limitations.

## 5. Hardened v3 regression and benchmarking

```bash
python -m pytest -q -m 'not integration'
python -m pytest -q -m integration tests/test_hardening_regressions.py
python -m shielded_mempool attack-network --out results/new_clone_attack
python -m shielded_mempool faults --out results/new_fault_and_recovery
python -m shielded_mempool benchmark --sizes 1 2 --repeat 2 --warmup 1 --out results/new_smoke
```

For true p50/p95 statistics, run `--repeat 20` or more, with warm-up discarded, sufficient machine capacity, and explicit CPU quota disclosure. The code supports `--sizes 1 2 4 8 16 32 64 128 256`, but such a sweep is **not** included as a completed performance result. `results/hardened` contains new test artifacts and the short smoke measurements; previous `results/v2` files refer to the original code and use different latency definitions. Combined multiprocessing integration runs may stall in constrained test environments; isolated tests have clearer provenance.

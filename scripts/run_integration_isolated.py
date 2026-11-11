"""Run each multiprocess integration test in a fresh Python interpreter.

Prevents resource buildup in environments with constrained spawn semantics.
"""
import json, subprocess,sys,time
from pathlib import Path
TESTS=[
 'tests/test_gateway_v2.py::test_gateway_actual_client_rpc_with_committee',
 'tests/test_gateway_v2.py::test_attacks_through_real_sixteen_processes',
 'tests/test_gateway_v2.py::test_keystore_and_pending_queue_survive_restart',
 'tests/test_network.py::test_00_real_sixteen_process_threshold_block',
 'tests/test_network.py::test_finality_gate_rejects_early_release',
 'tests/test_network.py::test_invalid_shares_and_quorum_failure',
 'tests/test_hardening_regressions.py::test_first_t_verified_not_all_nodes',
 'tests/test_hardening_regressions.py::test_failed_proposal_reuses_identical_block_after_nodes_return',
 'tests/test_hardening_regressions.py::test_finalized_unopened_recovery_without_changing_block',
 'tests/test_hardening_regressions.py::test_failed_queued_proposal_persists_for_new_coordinator',
 'tests/test_hardening_regressions.py::test_cached_block_validation_not_bypassed_by_reusing_hash',
 'tests/test_hardening_regressions.py::test_certified_unopened_survives_process_restart_with_same_keystore',
]
if __name__=='__main__':
    records=[]
    dest=Path('results/hardened/integration_isolated.json');dest.parent.mkdir(parents=True,exist_ok=True)
    for name in TESTS:
        print('RUN',name,flush=True)
        t0=time.perf_counter()
        try:
            result=subprocess.run([sys.executable,'-m','pytest','-q','-m','integration',name],
                                  text=True,capture_output=True,timeout=60)
            okay=result.returncode==0
            records.append({'test':name,'passed':okay,'elapsed_s':round(time.perf_counter()-t0,2),
                            'stdout':result.stdout[-500:],'stderr':result.stderr[-500:]})
            print(('PASS' if okay else 'FAIL'),name,records[-1]['elapsed_s'],flush=True)
        except subprocess.TimeoutExpired:
            records.append({'test':name,'passed':False,'elapsed_s':round(time.perf_counter()-t0,2),
                            'error':'timed out after 60 seconds'})
            print('TIMEOUT',name,flush=True)
        dest.write_text(json.dumps(records,indent=2)+'\n')
    print('Summary:',sum(r['passed'] for r in records),'/',len(records),'passed',flush=True)
    sys.exit(0 if all(r['passed'] for r in records) else 1)

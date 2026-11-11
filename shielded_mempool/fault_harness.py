"""Single-committee fault evaluation, avoiding repeated process startup.

All 16 separate committee processes remain alive across scenarios.  An
unreachable node is simulated by omitting its RPC from that block. Research
fault injection uses an authenticated, localhost-only test control message.
"""
from __future__ import annotations
import asyncio
import time
from .cluster import Cluster
from .engine import Coordinator,QuorumError

SCENARIOS=[
 ('healthy',set(),set(),set(),set()),
 ('two_offline',{1,2},set(),set(),set()),
 ('five_offline',{1,2,3,4,5},set(),set(),set()),
 ('three_invalid',set(),set(),{1,2,3},set()),
 ('three_withhold',set(),{1,2,3},set(),set()),
 ('six_offline_fails',{1,2,3,4,5,6},set(),set(),set()),
 # A six-offline failure must NOT brick the height; explicitly verify recovery
 # by retrying the original hash when nodes return before this final case.
 ('slow_committee',set(),set(),set(),{1,2,3,4,5})
]

async def _run(cl:Cluster,B:int):
    coord=Coordinator(cl,rpc_timeout=20)
    rows=[]
    for name,offline,withholding,corrupt,slow in SCENARIOS:
        cl.offline=set()  # Configure all 16 processes, then inject reachability fault.
        await cl.configure_faults(withhold=withholding,corrupt=corrupt,slow=slow,delay_ms=250)
        cl.offline=set(offline)
        t0=time.perf_counter()
        try:
            result=await coord.run_block(B)
            row={'scenario':name,'success':True,'latency_ms':result['total_ms'],
                 'online_nodes':16-len(offline),
                 'rejected_shares':result['invalid_share_nodes'],
                 'block_height':result['block_height']}
        except QuorumError as exc:
            row={'scenario':name,'success':False,'latency_ms':round((time.perf_counter()-t0)*1000,3),
                 'online_nodes':16-len(offline),'error':str(exc)}
        rows.append(row)
        print(f'  {name}: {row["success"]} in {row["latency_ms"]:.0f} ms',flush=True)
        if name=='six_offline_fails':
            assert not row['success'], 'Fault test did not remove a quorum'
            previous_hash=coord._staged_synthetic[0]['block_hash']
            cl.offline.clear()
            # Same coordinator, same staged block, same height, no rerandomization.
            started=time.perf_counter()
            reopened=await coord.run_block(B)
            assert reopened['block_hash']==previous_hash
            rows.append({'scenario':'six_offline_recovery','success':True,
                         'latency_ms':round((time.perf_counter()-started)*1000,3),
                         'online_nodes':16,'same_block_hash':True,
                         'block_height':reopened['block_height']})
            print('  six_offline_recovery: identical certified hash',flush=True)
    return rows

def run_fault_suite(B:int=1)->list[dict]:
    with Cluster(n=16,t=11) as cl:
        return asyncio.run(_run(cl,B))

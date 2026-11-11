"""Regression: five 4-second responders must not delay an 11-of-16 quorum."""
import asyncio
import json
import pathlib
import time
from shielded_mempool.cluster import Cluster
from shielded_mempool.engine import Coordinator


def main():
    with Cluster(n=16,t=11,slow=set(range(1,6)),extra_delay_ms=4000) as cluster:
        begin=time.perf_counter()
        block=asyncio.run(Coordinator(cluster,rpc_timeout=8).run_block(1))
        elapsed=(time.perf_counter()-begin)*1000
        result={'committee':16,'threshold':11,'slow_nodes':5,'configured_delay_ms':4000,
                'wall_elapsed_ms':round(elapsed,3),'valid_share_nodes':block['valid_share_nodes'],
                'post_finality_ms':block['post_finality_ms'],
                'node_cpu_p50_ms':block['node_partial_cpu_p50_ms'],
                'node_wall_p50_ms':block['node_partial_crypto_p50_ms'],
                'successful_without_waiting_four_seconds':elapsed<4000}
    out=pathlib.Path('results/hardened/fast_11_of_16.json')
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2),flush=True)
    if not result['successful_without_waiting_four_seconds']:
        raise SystemExit('FAILED: committee waited for slow nodes')

if __name__=='__main__':main()

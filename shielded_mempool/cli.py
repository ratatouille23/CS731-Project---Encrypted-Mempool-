"""CLI: demonstration, repeated benchmarks, fault injection, privacy, plots."""
from __future__ import annotations
import argparse
import csv
import json
import pathlib
import statistics
import sys
import time
from .attacks import run_malleability_demo, run_epoch_leak_demo, run_clone_regression_demo
from .cluster import Cluster
from .engine import benchmark_once, Coordinator, QuorumError
from .privacy import experiment
from .crypto import P, Q


def write_json(folder: pathlib.Path, name: str, data) -> pathlib.Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {path}")
    return path


def write_csv(folder: pathlib.Path, name: str, rows: list[dict]) -> None:
    if not rows:
        return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with (folder / name).open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', choices=['demo','attack','attack-network','benchmark','benchmark-queue','toy-btx','mev-demo','faults','privacy','serve','all'],default='demo')
    parser.add_argument('--out', default='results', help='Directory for JSON and CSV artifacts')
    parser.add_argument('--sizes', nargs='+', type=int, default=[1, 2, 4], help='Block sizes for benchmarks')
    parser.add_argument('--repeat', type=int, default=1, help='Measured repetitions; use >=20 for meaningful p95')
    parser.add_argument('--warmup',type=int,default=0,help='Discard this many warm-up blocks per batch size')
    parser.add_argument('--delay-ms', type=float, default=0.0, help='Artificial response delay per node per RPC')
    parser.add_argument('--fault-batch', type=int, default=1, help='Transactions per fault-scenario block')
    parser.add_argument('--privacy-samples', type=int, default=160)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--port',type=int,default=8765,help='Gateway port for serve')
    parser.add_argument('--db',default=':memory:',help='SQLite mempool file (requires --keys for persistence)')
    parser.add_argument('--keys',default=None,help='Encrypted committee keystore (password via SHIELDED_MEMPOOL_KEYSTORE_PASSWORD)')
    parser.add_argument('--fault-only',default=None,help='Run only this named fault scenario')
    args = parser.parse_args(argv)
    if args.repeat < 1 or args.warmup < 0 or any(x <= 0 for x in args.sizes):
        parser.error('Repetitions and batch sizes must be positive')
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print(f"ShieldedMempool research prototype | MODP p={P.bit_length()}bits, q={Q.bit_length()}bits")

    if args.command == 'serve':
        import asyncio
        from .gateway import Gateway
        from .mempool import Mempool
        import os
        if args.db != ':memory:' and not args.keys:
            parser.error('a persistent mempool needs --keys to retain the same committee key')
        with Cluster(n=16,t=11,keys_path=args.keys,
                     key_password=os.environ.get('SHIELDED_MEMPOOL_KEYSTORE_PASSWORD')) as cluster:
            with Mempool(cluster.pub,args.db) as mempool:
                asyncio.run(Gateway(cluster,mempool).serve(args.port))
        return 0

    if args.command == 'attack-network':
        from .network_attacks import run_network_attacks
        print('Running network attack scenarios over 16 real node processes...',flush=True)
        result=run_network_attacks()
        write_json(out,'network_attacks.json',result)
        if not result['passed']:
            return 1
        print('PASS: malleability attack, epoch leak and defended rejection',flush=True)
        return 0

    if args.command=='toy-btx':
        from .btx_algebra import toy_demo,index_collision_demo
        output={'btx_algebra':toy_demo(), 'beat_mev_index_collision':index_collision_demo()}
        write_json(out,'toy_btx.json',output)
        print(json.dumps(output,indent=2))
        return 0

    if args.command=='mev-demo':
        from .mev_sandbox import sandwich_demo
        result=sandwich_demo()
        write_json(out,'mev_sandbox.json',result)
        print(json.dumps(result,indent=2))
        return 0

    if args.command in ['attack', 'all']:
        a = run_malleability_demo()
        b = run_epoch_leak_demo()
        c = run_clone_regression_demo()
        write_json(out, 'attacks.json', {'malleability': a, 'epoch_key_leak': b,
                                        'clone_regression': c})
        print('Malleability recovered:', a['naive_attack_recovered_original'],
              '| defended rejected:', a['defended_related_ciphertext_rejected_before_share_release'])

    if args.command in ['privacy', 'all']:
        results = experiment(args.privacy_samples, args.seed)
        write_json(out, 'privacy.json', results)
        write_csv(out, 'privacy.csv', results)
        for item in results:
            print(f"  {item['policy']:<16} match={str(item['linked_fraction']):>6} "
                  f"delay_ms={item['mean_added_delay_ms']:.1f} pad={item['mean_padding_bytes']:.1f}")

    if args.command in ['demo', 'benchmark', 'benchmark-queue','all']:
        print('Spawning 16 independent TCP node processes (11-of-16 threshold)...', flush=True)
        with Cluster(n=16, t=11, delay_ms=args.delay_ms) as cluster:
            if args.command == 'demo':
                rows = benchmark_once(cluster, [1], 1)
                write_json(out, 'demo.json', rows)
                print('Encrypted 1-tx block:', json.dumps(rows[-1], indent=2))
            else:
                if args.command=='benchmark-queue':
                    from .engine import benchmark_queue_once
                    rows=benchmark_queue_once(cluster,args.sizes,args.repeat,warmup=args.warmup)
                else:
                    rows = benchmark_once(cluster, args.sizes, args.repeat,warmup=args.warmup)
                write_json(out, 'benchmark.json', rows)
                write_csv(out, 'benchmark.csv', rows)
                from .benchmarking import write_summary
                write_summary(out,rows)
                if args.repeat<20:
                    print('WARNING: fewer than 20 repetitions; p95/p99 are exploratory only.',flush=True)
                for encrypted in [x for x in rows if x['mode'] == 'threshold_encrypted']:
                    added=encrypted.get('added_block_latency_ms',encrypted.get('post_finality_ms'))
                    print(f"B={encrypted['batch_size']:3d}, total={encrypted['total_ms']:8.2f}ms, "
                          f"post_finality={encrypted['post_finality_ms']:8.2f}ms, "
                          f"added-critical={added:8.2f}ms")

    if args.command in ['faults','all']:
        import asyncio
        fault_rows = []
        scenarios = [
            ('healthy', set(), set(), set(), set()),
            ('two_offline', {1,2}, set(), set(), set()),
            ('five_offline', {1,2,3,4,5}, set(), set(), set()),
            ('three_invalid', set(), set(), {1,2,3}, set()),
            ('three_withhold', set(), {1,2,3}, set(), set()),
            ('six_offline_fails', {1,2,3,4,5,6}, set(), set(), set()),
            ('slow_committee', set(), set(), set(), {1,2,3,4,5}),
        ]
        if args.fault_only is None:
            from .fault_harness import run_fault_suite
            all_rows=run_fault_suite(args.fault_batch)
            write_json(out,'faults.json',all_rows)
            write_csv(out,'faults.csv',all_rows)
            return 0
        for name, offline, withholding, corrupt, slow in scenarios:
            if args.fault_only is not None and name != args.fault_only:
                continue
            print('Fault scenario:',name,flush=True)
            with Cluster(n=16,t=11, offline=offline,withhold=withholding,
                         corrupt=corrupt,slow=slow,extra_delay_ms=250,
                         delay_ms=args.delay_ms) as cluster:
                t0 = time.perf_counter()
                try:
                    row = asyncio.run(Coordinator(cluster,rpc_timeout=20).run_block(args.fault_batch))
                    fault_rows.append({'scenario':name,'success':True,'latency_ms':row['total_ms'],
                                       'rejected_shares':row['invalid_share_nodes'],'online_nodes':len(cluster.active_indices)})
                except QuorumError as e:
                    fault_rows.append({'scenario':name,'success':False,
                                       'latency_ms':round((time.perf_counter()-t0)*1000,3),
                                       'error':str(e),'online_nodes':len(cluster.active_indices)})
        write_json(out,'faults.json',fault_rows)
        write_csv(out,'faults.csv',fault_rows)
        for row in fault_rows:
            print(row['scenario'], 'PASS' if row['success'] else 'EXPECTED FAILURE', row['latency_ms'])

    return 0

if __name__ == '__main__':
    sys.exit(main())

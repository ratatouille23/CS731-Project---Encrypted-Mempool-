"""Repeatable descriptive benchmark summaries (no invented samples)."""
from __future__ import annotations
import csv
import math
import pathlib
import statistics
from collections import defaultdict

METRICS=(
    'block_critical_path_ms', 'post_finality_ms','order_finalize_ms',
    'ordering_extra_ms','committee_release_rpc_ms','release_with_verification_ms','verify_shares_ms','combine_aead_ms',
    'client_encrypt_ms','gateway_encrypt_and_admit_ms',
    'added_block_latency_ms','node_partial_crypto_p50_ms',
    'node_partial_cpu_p50_ms','node_partial_cpu_sum_ms')


def percentile(values:list[float],p:float)->float:
    """Linear interpolation of sample order statistics, no distribution model."""
    if not values:raise ValueError('No samples')
    ordered=sorted(values)
    pos=(len(ordered)-1)*p/100.0
    lo=int(math.floor(pos));hi=int(math.ceil(pos))
    return ordered[lo]+(ordered[hi]-ordered[lo])*(pos-lo)


def summarize(rows:list[dict])->list[dict]:
    groups=defaultdict(list)
    for row in rows:
        if row.get('warmup'):
            continue
        groups[(row.get('mode'),row.get('batch_size'))].append(row)
    output=[]
    for (mode,size),samples in sorted(groups.items(),key=lambda x:(str(x[0][0]),x[0][1])):
        rec={'mode':mode,'batch_size':size,'samples':len(samples),
             'stats_reliable':len(samples)>=20}
        for key in METRICS:
            vals=[float(r[key]) for r in samples if r.get(key) is not None]
            if not vals:continue
            rec[key+'_p50']=round(percentile(vals,50),3)
            rec[key+'_p95']=round(percentile(vals,95),3)
            rec[key+'_p99']=round(percentile(vals,99),3)
            rec[key+'_mean']=round(statistics.fmean(vals),3)
        output.append(rec)
    return output


def write_summary(folder:pathlib.Path,rows:list[dict])->list[dict]:
    folder.mkdir(parents=True,exist_ok=True)
    summary=summarize(rows)
    if not summary:return []
    keys=list(dict.fromkeys(k for row in summary for k in row))
    with (folder/'benchmark_summary.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(summary)
    import json
    (folder/'benchmark_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    try:
        plot_summary(folder,summary)
    except ImportError:
        pass
    return summary


def plot_summary(folder:pathlib.Path,summary:list[dict])->None:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    enc=[r for r in summary if r['mode']=='threshold_encrypted']
    plain={r['batch_size']:r for r in summary if r['mode']=='plaintext'}
    if not enc:return
    sizes=[r['batch_size'] for r in enc]
    # All phases are measured on the same critical path; client encryption is
    # deliberately NOT stacked into block processing time.
    ord_ms=[r.get('order_finalize_ms_p50',0) for r in enc]
    release_ms=[r.get('release_with_verification_ms_p50',0) for r in enc]
    opening_ms=[r.get('combine_aead_ms_p50',0) for r in enc]
    base=[plain.get(b,{}).get('block_critical_path_ms_p50',0) for b in sizes]
    fig,ax=plt.subplots(figsize=(10,5))
    x=list(range(len(sizes)));width=.36
    ax.bar([i-width/2 for i in x],base,width,label='Plaintext critical path')
    ax.bar([i+width/2 for i in x],ord_ms,width,label='Encrypted: validation + ordering')
    ax.bar([i+width/2 for i in x],release_ms,width,bottom=ord_ms,label='Encrypted: share RPC + share validation')
    ax.bar([i+width/2 for i in x],opening_ms,width,
           bottom=[a+b for a,b in zip(ord_ms,release_ms)],label='Encrypted: combination + AEAD')
    ax.set_xticks(x,sizes)
    ax.set_xlabel('Transactions per block B')
    ax.set_ylabel('Median wall-clock milliseconds')
    ax.set_title('Measured critical path (client encryption excluded)')
    ax.legend(fontsize=8)
    ax.grid(axis='y',alpha=.25)
    fig.tight_layout()
    fig.savefig(folder/'stacked_critical_path.png',dpi=180)
    plt.close(fig)

    fig,ax=plt.subplots(figsize=(8,4))
    ax.plot(sizes,[r.get('node_partial_crypto_p50_ms_p50',0) for r in enc],marker='o',label='Node partial decrypt wall time')
    ax.plot(sizes,[r.get('node_partial_cpu_p50_ms_p50',0) for r in enc],marker='s',label='Node partial decrypt CPU time')
    ax.set_xlabel('Transactions per block B')
    ax.set_ylabel('Median milliseconds')
    ax.set_title('Node CPU vs wall clock (oversubscription exposed)')
    ax.legend()
    ax.grid(alpha=.25)
    fig.tight_layout();fig.savefig(folder/'node_cpu_vs_wall.png',dpi=180);plt.close(fig)

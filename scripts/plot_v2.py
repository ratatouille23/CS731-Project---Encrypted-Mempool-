"""Generate actual queue-benchmark plots. No hidden or fabricated points."""
import argparse,json
from pathlib import Path
import matplotlib.pyplot as plt

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',default='results/v2/queue_benchmark/benchmark.json')
    parser.add_argument('--out',default='results/v2/plots')
    a=parser.parse_args()
    rows=json.loads(Path(a.input).read_text())
    rows=sorted(rows,key=lambda x:(x['batch_size'],x['repeat']))
    out=Path(a.out);out.mkdir(parents=True,exist_ok=True)
    B=[x['batch_size'] for x in rows]
    plt.figure(figsize=(8,4.3))
    plt.plot(B,[x['total_ms'] for x in rows],marker='o',label='Encrypted queued block')
    plt.plot(B,[x['plaintext_baseline_ms'] for x in rows],marker='o',label='Plaintext control')
    plt.xlabel('Transactions per block (B)')
    plt.ylabel('Measured block latency (ms)')
    plt.title('16-node 11-of-16 local prototype — one run per batch')
    plt.legend();plt.tight_layout();plt.savefig(out/'queue_latency.png',dpi=180);plt.close()
    labels=['Finality votes','Share RPC','Proof checks','Share combine+AEAD']
    phases=['order_finalize_ms','committee_release_rpc_ms','verify_shares_ms','combine_aead_ms']
    plt.figure(figsize=(8,4.3));bottom=[0]*len(B)
    for label,phase in zip(labels,phases):
        vals=[x[phase] for x in rows]
        plt.bar([str(x) for x in B],vals,bottom=bottom,label=label)
        bottom=[u+v for u,v in zip(bottom,vals)]
    plt.xlabel('Transactions per block (B)');plt.ylabel('Milliseconds')
    plt.title('End-to-end critical-path breakdown (single runs)')
    plt.legend();plt.tight_layout();plt.savefig(out/'queue_phase_breakdown.png',dpi=180);plt.close()
    print(f'Wrote {out}/queue_latency.png and queue_phase_breakdown.png')

if __name__=='__main__':main()

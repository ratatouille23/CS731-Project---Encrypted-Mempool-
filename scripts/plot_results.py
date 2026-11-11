"""Create charts from actual recorded output; does not invent benchmark data."""
import csv
from pathlib import Path
import sys
import matplotlib.pyplot as plt

folder = Path(sys.argv[1] if len(sys.argv) > 1 else 'results')
plot_dir = folder / 'plots'
plot_dir.mkdir(parents=True, exist_ok=True)

bench = folder/'benchmark.csv'
if bench.exists():
    with bench.open() as f:
        data = list(csv.DictReader(f))
    xs = sorted({int(x['batch_size']) for x in data})
    plt.figure(figsize=(8,5))
    for name in ['plaintext','threshold_encrypted']:
        ys = [sum(float(x['total_ms']) for x in data if x['mode']==name and int(x['batch_size'])==b) /
              max(1,sum(1 for x in data if x['mode']==name and int(x['batch_size'])==b)) for b in xs]
        plt.plot(xs, ys, marker='o', label=name)
    plt.xlabel('Transactions per block')
    plt.ylabel('Mean end-to-end block latency (ms)')
    plt.title('Measured block latency by batch size')
    plt.legend()
    plt.grid(alpha=.2)
    plt.tight_layout()
    plt.savefig(plot_dir/'latency_vs_batch.png',dpi=180)
    plt.close()

    names=['client_encrypt_ms','order_finalize_ms','committee_release_rpc_ms','verify_shares_ms','combine_aead_ms']
    size=max(xs)
    filtered=[x for x in data if x['mode']=='threshold_encrypted' and int(x['batch_size'])==size]
    means=[sum(float(row[k]) for row in filtered)/len(filtered) for k in names]
    plt.figure(figsize=(8,5))
    plt.barh([x.replace('_',' ') for x in names],means)
    plt.xlabel('Mean elapsed time (ms)')
    plt.title(f'Actual measured phase costs, B={size}')
    plt.tight_layout()
    plt.savefig(plot_dir/'latency_breakdown.png',dpi=180)
    plt.close()

privacy=folder/'privacy.csv'
if privacy.exists():
    with privacy.open() as f:
        data=list(csv.DictReader(f))
    valid=[x for x in data if x['linked_fraction'] not in ('','None')]
    plt.figure(figsize=(8,5))
    plt.bar([x['policy'] for x in valid], [float(x['linked_fraction']) for x in valid])
    plt.ylim(0,1)
    plt.xticks(rotation=20,ha='right')
    plt.ylabel('Attacker correct matching fraction')
    plt.title('Synthetic RPC simulation-to-submission linkage')
    plt.tight_layout()
    plt.savefig(plot_dir/'privacy_linkage.png',dpi=180)
    plt.close()
print('Wrote plots in',plot_dir)

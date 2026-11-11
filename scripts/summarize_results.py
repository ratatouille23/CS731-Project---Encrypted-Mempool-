"""Calculate per-size p50/p95/p99 using empirical CSV samples only."""
import csv
import json
import sys
from pathlib import Path

root=Path(sys.argv[1] if len(sys.argv)>1 else 'results')
with (root/'benchmark.csv').open(newline='') as f:
    rows=list(csv.DictReader(f))

def percentile(xs,q):
    vals=sorted(float(x) for x in xs)
    if not vals:return None
    pos=(len(vals)-1)*q
    a=int(pos)
    return vals[a] + (vals[min(a+1,len(vals)-1)]-vals[a])*(pos-a)

summary=[]
for mode in sorted(set(x['mode'] for x in rows)):
    for b in sorted(set(int(x['batch_size']) for x in rows)):
        items=[x for x in rows if x['mode']==mode and int(x['batch_size'])==b]
        vals=[float(x['total_ms']) for x in items]
        summary.append({'mode':mode,'batch_size':b,'repetitions':len(vals),
                        'latency_mean_ms':round(sum(vals)/len(vals),3),
                        'latency_p50_ms':round(percentile(vals,.5),3),
                        'latency_p95_ms':round(percentile(vals,.95),3) if len(vals)>=20 else None,
                        'latency_p99_ms':round(percentile(vals,.99),3) if len(vals)>=100 else None})
(root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
print('Note: p95 requires >=20 repetitions; p99 requires >=100, otherwise null.')

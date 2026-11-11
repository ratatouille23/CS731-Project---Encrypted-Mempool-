"""Includes a true 16-process integration test; smaller committees for fault unit cases."""
import asyncio
import json
import subprocess
import sys
import pytest
from shielded_mempool.cluster import Cluster, rpc
from shielded_mempool.engine import Coordinator, QuorumError
from shielded_mempool.crypto import encrypt
from shielded_mempool.protocol import build_block, GENESIS_HASH

@pytest.mark.integration
def test_00_real_sixteen_process_threshold_block(tmp_path):
    # Use the same standalone CLI the user runs. Running 16 spawn processes
    # within a pytest plugin-loaded parent can be unstable on constrained CI.
    run = subprocess.run([sys.executable, '-m', 'shielded_mempool', 'demo',
                          '--out', str(tmp_path)], capture_output=True,
                         text=True, timeout=90)
    assert run.returncode == 0, run.stdout + '\n' + run.stderr
    rows = json.loads((tmp_path / 'demo.json').read_text())
    row = rows[-1]
    assert row['committee'] == 16 and row['threshold'] == 11
    assert row['plaintext_integrity']
    assert row['valid_share_nodes'] >= 11
    assert row['post_finality_ms'] > 0

@pytest.mark.integration
def test_finality_gate_rejects_early_release():
    with Cluster(n=3,t=2) as cl:
        env=encrypt(cl.pub,b'secret')
        block=build_block(1,GENESIS_HASH,[env])
        r,_,_=asyncio.run(rpc(cl.ports[1],{'op':'release','block':block,'certificate':[]}))
        assert not r['ok']
        r,_,_=asyncio.run(rpc(cl.ports[1],{'op':'propose','block':block}))
        assert r['ok']
        r,_,_=asyncio.run(rpc(cl.ports[1],{'op':'release','block':block,'certificate':[]}))
        assert not r['ok']

@pytest.mark.integration
def test_invalid_shares_and_quorum_failure():
    with Cluster(n=5,t=3, corrupt={1,2}) as cl:
        row=asyncio.run(Coordinator(cl).run_block(1))
        assert row['invalid_share_nodes']==2
        assert row['valid_share_nodes']>=3
    with Cluster(n=5,t=3, offline={1,2,3}) as cl:
        with pytest.raises(QuorumError):
            asyncio.run(Coordinator(cl).run_block(1))

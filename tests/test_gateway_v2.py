import asyncio
import subprocess
import sys
import json
import pytest
from shielded_mempool.cluster import Cluster
from shielded_mempool.gateway import Gateway,gateway_rpc
from shielded_mempool.mempool import Mempool
from shielded_mempool.crypto import encrypt,public_from_json

@pytest.mark.integration
def test_gateway_actual_client_rpc_with_committee():
    asyncio.run(_test_gateway_impl())

async def _test_gateway_impl():
    with Cluster(n=3,t=2) as cl:
        with Mempool(cl.pub) as pool:
            gateway=Gateway(cl,pool)
            server=await asyncio.start_server(gateway.handler,'127.0.0.1',0)
            port=server.sockets[0].getsockname()[1]
            async with server:
                info=await gateway_rpc(port,{'op':'info'})
                pub=public_from_json(info['public_key'])
                a=encrypt(pub,b'PAYLOAD A');b=encrypt(pub,b'PAYLOAD B')
                assert (await gateway_rpc(port,{'op':'submit','transaction':a,'priority':3}))['ok']
                assert (await gateway_rpc(port,{'op':'submit','transaction':b,'priority':9}))['ok']
                assert not (await gateway_rpc(port,{'op':'submit','transaction':a,'priority':3}))['ok']
                first=await gateway_rpc(port,{'op':'mine','limit':1,'policy':'priority'})
                assert first['ok'],first
                assert bytes.fromhex(first['block']['opened_payloads_hex'][0])==b'PAYLOAD B'
                assert (await gateway_rpc(port,{'op':'status','txid':a['txid']}))['transaction']['status']=='pending'
                second=await gateway_rpc(port,{'op':'mine','limit':1})
                assert second['ok'],second
                assert bytes.fromhex(second['block']['opened_payloads_hex'][0])==b'PAYLOAD A'
                assert (await gateway_rpc(port,{'op':'info'}))['queue']['pending']==0

@pytest.mark.integration
def test_attacks_through_real_sixteen_processes(tmp_path):
    run=subprocess.run([sys.executable,'-m','shielded_mempool','attack-network',
                        '--out',str(tmp_path)],capture_output=True,text=True,timeout=110)
    assert run.returncode==0,run.stdout+'\n'+run.stderr
    result=json.loads((tmp_path/'network_attacks.json').read_text())
    assert result['passed']

@pytest.mark.integration
def test_keystore_and_pending_queue_survive_restart(tmp_path):
    from shielded_mempool.engine import Coordinator
    path=str(tmp_path/'pool.db'); keys=str(tmp_path/'keys.enc')
    password='a secure demonstration passphrase'
    with Cluster(n=3,t=2,keys_path=keys,key_password=password) as cl:
        with Mempool(cl.pub,path) as pool:
            first=encrypt(cl.pub,b'block-one');second=encrypt(cl.pub,b'block-two')
            pool.submit(first);pool.submit(second)
            row=asyncio.run(Coordinator(cl,pool).run_submitted_block(1))
            assert row['block_height']==1 and pool.stats()['pending']==1
    with Cluster(n=3,t=2,keys_path=keys,key_password=password) as cl:
        with Mempool(cl.pub,path) as pool:
            c=Coordinator(cl,pool)
            assert c.height==2
            row=asyncio.run(c.run_submitted_block(1))
            assert row['block_height']==2
            assert pool.stats()['pending']==0
            assert bytes.fromhex(row['opened_payloads_hex'][0])==b'block-two'

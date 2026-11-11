"""Public TCP gateway: external encrypted submissions, status and mining.

Run: python -m shielded_mempool serve --port 8765 --db results/mempool.sqlite
Client: python scripts/gateway_client.py --port 8765 submit --message '...'
All gateway connections are local-only; add transport authentication and rate
limiting before use on an untrusted network.
"""
from __future__ import annotations
import asyncio
import json
from .crypto import public_as_json
from .engine import Coordinator
from .mempool import Mempool,RejectedTransaction
from .cluster import Cluster

MAX_MESSAGE=2*1024*1024


class Gateway:
    def __init__(self,cl:Cluster,pool:Mempool):
        self.cl=cl
        self.pool=pool
        self.coord=Coordinator(cl,pool)
        self.mine_lock=asyncio.Lock()

    async def request(self,req:dict)->dict:
        op=req.get('op')
        if op=='info':
            return {'ok':True,'public_key':public_as_json(self.cl.pub),
                    'head_height':self.coord.height-1,
                    'queue':self.pool.stats()}
        if op=='submit':
            try:
                txid=self.pool.submit(req['transaction'],fee_priority=req.get('priority',0))
                return {'ok':True,'txid':txid,'status':'pending'}
            except (KeyError,ValueError,RejectedTransaction,TypeError) as e:
                return {'ok':False,'error':str(e)}
        if op=='status':
            status=self.pool.status(str(req.get('txid','')))
            return {'ok':status is not None,'transaction':status}
        if op=='pending':
            txs=self.pool.pending(limit=min(max(int(req.get('limit',20)),1),100),
                                   policy=str(req.get('policy','fifo')))
            # Show only identifiers and public metadata, not ciphertext blobs.
            return {'ok':True,'ids':[tx['txid'] for tx in txs], 'count':len(txs)}
        if op=='mine':
            async with self.mine_lock:
                try:
                    result=await self.coord.run_submitted_block(limit=min(max(int(req.get('limit',4)),1),512),
                                                                policy=str(req.get('policy','fifo')))
                    return {'ok':True,'block':result}
                except (ValueError,RuntimeError) as e:
                    return {'ok':False,'error':str(e)}
        return {'ok':False,'error':'unknown operation'}

    async def handler(self,reader:asyncio.StreamReader,writer:asyncio.StreamWriter)->None:
        try:
            data=await asyncio.wait_for(reader.readline(),timeout=120)
            if len(data)>MAX_MESSAGE:
                raise ValueError('request too large')
            req=json.loads(data)
            response=await self.request(req)
        except Exception as e:
            response={'ok':False,'error':f'{type(e).__name__}: {str(e)[:240]}'}
        writer.write(json.dumps(response,separators=(',',':')).encode()+b'\n')
        try: await writer.drain()
        finally:
            writer.close(); await writer.wait_closed()

    async def serve(self,port:int,host:str='127.0.0.1')->None:
        server=await asyncio.start_server(self.handler,host,port,limit=MAX_MESSAGE+1024)
        print(f'ShieldedMempool Gateway listening on {host}:{port}',flush=True)
        async with server:
            await server.serve_forever()


async def gateway_rpc(port:int,request:dict,host:str='127.0.0.1')->dict:
    reader,writer=await asyncio.open_connection(host,port,limit=MAX_MESSAGE+1024)
    try:
        writer.write(json.dumps(request,separators=(',',':')).encode()+b'\n')
        await writer.drain()
        reply=await asyncio.wait_for(reader.readline(),timeout=180)
        return json.loads(reply)
    finally:
        writer.close(); await writer.wait_closed()

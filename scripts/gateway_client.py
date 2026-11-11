"""Command-line client for the running 16-node gateway.

Examples:
  python scripts/gateway_client.py submit --message 'BUY 100 ETH' --priority 5
  python scripts/gateway_client.py pending
  python scripts/gateway_client.py mine --limit 3
  python scripts/gateway_client.py info
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from shielded_mempool.gateway import gateway_rpc
from shielded_mempool.crypto import public_from_json,encrypt

async def action(args):
    op=args.command
    if op=='submit':
        info=await gateway_rpc(args.port,{'op':'info'},args.host)
        if not info.get('ok'):raise RuntimeError('gateway unavailable')
        pub=public_from_json(info['public_key'])
        env=encrypt(pub,args.message.encode(),metadata={'sender':args.sender,'fee_class':args.priority},pad_to=args.pad_to)
        reply=await gateway_rpc(args.port,{'op':'submit','transaction':env,'priority':args.priority},args.host)
    elif op=='mine':
        reply=await gateway_rpc(args.port,{'op':'mine','limit':args.limit,'policy':args.policy},args.host)
        if reply.get('ok'):
            reply['block']['opened_payloads_utf8']=[bytes.fromhex(x).decode(errors='replace') for x in reply['block']['opened_payloads_hex']]
    elif op=='pending':
        reply=await gateway_rpc(args.port,{'op':'pending','limit':args.limit,'policy':args.policy},args.host)
    elif op=='status':
        reply=await gateway_rpc(args.port,{'op':'status','txid':args.txid},args.host)
    else:
        reply=await gateway_rpc(args.port,{'op':'info'},args.host)
    print(json.dumps(reply,indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['submit','mine','info','pending','status'])
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--message',default='SWAP 1 ETH FOR TOKEN A')
    parser.add_argument('--sender',default='demo_wallet')
    parser.add_argument('--priority',type=int,default=0)
    parser.add_argument('--pad-to',type=int,default=0)
    parser.add_argument('--policy',choices=['fifo','priority'],default='fifo')
    parser.add_argument('--limit',type=int,default=4)
    parser.add_argument('--txid',default='')
    asyncio.run(action(parser.parse_args()))

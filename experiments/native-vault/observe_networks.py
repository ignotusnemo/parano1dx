"""Read-only RPC observations for planning live latency measurements.

Records endpoint response times and block/slot cadence. No transaction is
submitted. These observations are distinct from withdrawal inclusion time.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import datetime,json,statistics,time,urllib.request

ALLOWED={'eth_chainId','eth_getBlockByNumber','getSlot','getRecentPerformanceSamples'}
def call(url,method,params):
    assert method in ALLOWED
    request=urllib.request.Request(url,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),
        headers={'Content-Type':'application/json','User-Agent':'Parano1dX-local-research/0.1'})
    start=time.perf_counter()
    with urllib.request.urlopen(request,timeout=8) as response:body=json.load(response)
    elapsed=(time.perf_counter()-start)*1000
    if 'error' in body:raise RuntimeError(str(body['error']))
    return body['result'],elapsed
def observe(name,endpoints):
    errors=[]
    for url in endpoints:
        try:
            samples=[]
            for _ in range(5):
                result,ms=call(url,'eth_chainId' if name=='Base' else 'getSlot',[])
                if name=='Base':assert int(result,16)==8453
                samples.append(ms)
            item={'endpoint':url,'fresh_https_request_ms':samples,'median_ms':statistics.median(samples)}
            if name=='Base':
                head,_=call(url,'eth_getBlockByNumber',['latest',False]);height=int(head['number'],16)
                prior,_=call(url,'eth_getBlockByNumber',[hex(height-100),False])
                item.update(block_number=height,block_hash=head['hash'],block_gas_limit=int(head['gasLimit'],16),
                    observed_mean_block_interval_ms=(int(head['timestamp'],16)-int(prior['timestamp'],16))*10)
            else:
                performance,_=call(url,'getRecentPerformanceSamples',[1]);sample=performance[0]
                item.update(performance_sample=sample,observed_mean_slot_interval_ms=1000*sample['samplePeriodSecs']/sample['numSlots'])
            return name,item
        except Exception as e:errors.append({'endpoint':url,'error':str(e)})
    return name,{'unavailable':True,'attempts':errors}
if __name__=='__main__':
    with ThreadPoolExecutor(2) as pool:
        futures=[pool.submit(observe,'Base',['https://mainnet.base.org','https://base-rpc.publicnode.com']),
            pool.submit(observe,'Solana',['https://api.mainnet-beta.solana.com','https://solana-rpc.publicnode.com'])]
        networks=dict(f.result() for f in futures)
    result={'observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'broadcast_transactions':0,
        'scope':'Fresh HTTPS RPC round trips from the recorded research host and recent chain cadence. Withdrawal inclusion and finality require live transaction measurements.',
        'networks':networks}
    target=Path(__file__).resolve().parent/'results/network-observations.json'
    target.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

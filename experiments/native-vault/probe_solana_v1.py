"""A signed large-message capability probe, restricted to public Devnet."""
from pathlib import Path
import base64,datetime,json,sys,time,urllib.request
sys.path.insert(0,sys.argv[1])
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.instruction import Instruction
from solders.message import MessageV1,TransactionConfig
from solders.transaction import VersionedTransaction

wallets=Path(sys.argv[2]);output=Path(sys.argv[3]);endpoint='https://api.devnet.solana.com'
def rpc(method,params=[]):
    req=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),
        headers={'Content-Type':'application/json','User-Agent':'Parano1dX-v1-research/0.1'})
    with urllib.request.urlopen(req,timeout=20) as response:body=json.load(response)
    if 'error' in body:raise RuntimeError(json.dumps(body['error']))
    return body['result']
genesis=rpc('getGenesisHash');assert genesis=='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'
feature=rpc('getAccountInfo',['txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL',{'encoding':'base64','commitment':'finalized'}])['value']
assert feature
feature_raw=base64.b64decode(feature['data'][0]);assert feature_raw[0]==1
fee_file=wallets/'funder.json';assert fee_file.stat().st_mode&0o077==0
payer=Keypair.from_bytes(bytes(json.loads(fee_file.read_text())))
memo=(b'Parano1dX public Devnet v1 transport probe. '+b'x'*3100)
instruction=Instruction(Pubkey.from_string('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),memo,[])
recent=rpc('getLatestBlockhash',[{'commitment':'confirmed'}])['value']
message=MessageV1.try_compile(payer.pubkey(),[instruction],Hash.from_string(recent['blockhash']),
    TransactionConfig(compute_unit_limit=1400000,loaded_accounts_data_size_limit=2097152))
tx=VersionedTransaction(message,[payer]);raw=bytes(tx);assert 1232<len(raw)<=4096 and raw[0]==0x81
sim=rpc('simulateTransaction',[base64.b64encode(raw).decode(),{'encoding':'base64','commitment':'confirmed','sigVerify':True}])
assert sim['value']['err'] is None,sim
signature=rpc('sendTransaction',[base64.b64encode(raw).decode(),{'encoding':'base64','skipPreflight':False,'maxRetries':3}])
assert signature==str(tx.signatures[0]);began=time.monotonic()
while time.monotonic()-began<120:
    status=rpc('getSignatureStatuses',[[signature],{'searchTransactionHistory':True}])['value'][0]
    if status:
        assert status['err'] is None,status
        if status['confirmationStatus']=='finalized':break
    time.sleep(1)
else:raise TimeoutError('V1 finality deadline')
receipt=rpc('getTransaction',[signature,{'encoding':'json','commitment':'finalized','maxSupportedTransactionVersion':1}])
assert receipt and receipt['version']==1 and receipt['meta']['err'] is None
result={'network':'Solana Devnet','genesis_hash':genesis,'checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'feature_address':'txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL','feature_activation_slot':int.from_bytes(feature_raw[1:9],'little'),
    'transaction_version':1,'transaction_bytes':len(raw),'transaction_base64':base64.b64encode(raw).decode(),
    'signature':signature,'finalized':True,'receipt':receipt,'real_assets_used':False}
output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('receipt','transaction_base64')},indent=2))

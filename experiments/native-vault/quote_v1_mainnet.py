"""Read-only Mainnet feature, v1 signature-fee layouts and rent quote."""
from pathlib import Path
import base64,datetime,hashlib,json,sys,time,urllib.request,urllib.error
sys.path.insert(0,sys.argv[1])
from solders.transaction import VersionedTransaction
from solders.message import MessageV1,to_bytes_versioned
from solders.hash import Hash

case=Path(sys.argv[2]);local=not (case/'live-result.json').exists()
receipt_bytes=(case/('solana-vault.json' if local else 'live-result.json')).read_bytes();r=json.loads(receipt_bytes)
assert r['transaction_version']=='v1'
assert r['positive_lifecycle_completed'] and r['proof_buffer_rent_refunded'] if local else r['payout_and_nonce_checked'] and r['reserve_refunded']
endpoint='https://api.mainnet-beta.solana.com'
allowed={'getGenesisHash','getAccountInfo','getLatestBlockhash','getFeeForMessage','getMinimumBalanceForRentExemption','getSlot'}
def rpc(method,params=[]):
    assert method in allowed
    for attempt in range(6):
        request=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json','User-Agent':'Parano1dX-read-only-quote/0.1'})
        try:
            with urllib.request.urlopen(request,timeout=20) as response:body=json.load(response)
            if 'error' in body:raise RuntimeError(json.dumps(body['error']))
            time.sleep(.3);return body['result']
        except urllib.error.HTTPError as error:
            if error.code!=429 or attempt==5:raise
            time.sleep(float(error.headers.get('Retry-After','3'))+attempt)
genesis=rpc('getGenesisHash');assert genesis=='5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'
feature=rpc('getAccountInfo',['txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL',{'encoding':'base64','commitment':'finalized'}])['value']
assert feature;data=base64.b64decode(feature['data'][0]);assert data[0]==1
recent=rpc('getLatestBlockhash',[{'commitment':'confirmed'}])['value'];blockhash=Hash.from_string(recent['blockhash'])
unique={row['signature']:row for row in r['records' if local else 'transactions'] if row['scope']=='authorization'}
layouts={};counts={}
for row in unique.values():
    raw=base64.b64decode(row['transaction_base64']);tx=VersionedTransaction.from_bytes(raw);tx.verify_and_hash_message()
    assert raw[0]==0x81 and not tx.message.config.priority_fee
    n=tx.message.header.num_required_signatures;counts[n]=counts.get(n,0)+1
    if n not in layouts or len(raw)>layouts[n][0]:layouts[n]=(len(raw),tx.message)
quotes=[]
for signatures,(wire_bytes,message) in sorted(layouts.items()):
    m=MessageV1(message.header,message.config,blockhash,message.account_keys,message.instructions)
    wire=to_bytes_versioned(m);assert wire[0]==0x81
    fee=rpc('getFeeForMessage',[base64.b64encode(wire).decode(),{'commitment':'confirmed'}])
    assert fee['value']==5000*signatures
    quotes.append({'required_signatures':signatures,'transactions_in_measured_job':counts[signatures],
        'largest_signed_transaction_bytes':wire_bytes,'quoted_fee_lamports':fee['value'],'context_slot':fee['context']['slot']})
account_bytes=r['proof_buffer_space_bytes' if local else 'temporary_account_bytes']
reserve=rpc('getMinimumBalanceForRentExemption',[account_bytes,{'commitment':'confirmed'}])
total=sum(q['quoted_fee_lamports']*q['transactions_in_measured_job'] for q in quotes)
assert total==r['network_fee_lamports' if local else 'actual_network_fee_lamports']
result={'network':'Solana Mainnet','genesis_hash':genesis,'quoted_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'source_receipt_sha256':hashlib.sha256(receipt_bytes).hexdigest(),'v1_feature_active':True,
    'feature_activation_slot':int.from_bytes(data[1:9],'little'),'broadcast_transactions':0,
    'authorization_fee_lamports_by_observed_signer_layouts':total,'priority_fee_lamports':0,
    'temporary_account_bytes':account_bytes,'refundable_rent_lamports':reserve,'signer_layout_quotes':quotes,
    'fixture_scope':'Signed local v1 fixture with SBF instruction replay' if local else 'Signed public Devnet v1 fixture',
    'scope':'Read-only quote for the observed v1 signature layouts with a fresh Mainnet blockhash. Application deployment and relayer service charges are separate.'}
(case/'mainnet-layout-quote.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

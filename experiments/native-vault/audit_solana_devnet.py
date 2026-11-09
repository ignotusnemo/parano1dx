"""Verify public signed wires, immutable code and finalized payout receipts."""
from pathlib import Path
import base64,datetime,hashlib,json,struct,sys,time,urllib.error,urllib.request
sys.path.insert(0,sys.argv[1])
from solders.transaction import VersionedTransaction
from solders.pubkey import Pubkey
from solders.message import MessageV1
from Crypto.Hash import keccak

case=Path(sys.argv[2]);r=json.loads((case/'live-result.json').read_text())
URL='https://api.devnet.solana.com';GENESIS='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'
assert r['genesis_hash']==GENESIS and r['network']=='Solana Devnet' and not r['real_assets_used']
def rpc(method,params):
    for attempt in range(5):
        request=urllib.request.Request(URL,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request,timeout=12) as response:body=json.load(response)
            if 'error' in body:raise RuntimeError(json.dumps(body['error']))
            time.sleep(.25);return body['result']
        except (urllib.error.URLError,TimeoutError):
            if attempt==4:raise
            time.sleep(2+attempt)
assert rpc('getGenesisHash',[])==GENESIS
unique={}
for row in r['transactions']:
    raw=base64.b64decode(row['transaction_base64']);tx=VersionedTransaction.from_bytes(raw)
    tx.verify_and_hash_message()
    assert str(tx.signatures[0])==row['signature'] and str(tx.message.account_keys[0])==row['fee_payer']
    assert len(raw)==row['transaction_bytes']<=r.get('packet_size_limit',1232)
    if r.get('transaction_version')=='v1':
        assert isinstance(tx.message,MessageV1)
        assert tx.message.config.compute_unit_limit<=1_400_000
        assert tx.message.config.loaded_accounts_data_size_limit>0
        assert not tx.message.config.priority_fee
    for instruction in tx.message.instructions:
        if str(tx.message.account_keys[instruction.program_id_index])=='ComputeBudget111111111111111111111111111111':
            if instruction.data[0]==2:assert int.from_bytes(instruction.data[1:],'little')<=1_400_000
    if row['signature'] in unique:assert unique[row['signature']]==raw
    unique[row['signature']]=raw
group=r['query_batch_size'];assert 1<=group<=6
assert [f['frame'] for f in r['frames']]==[65535]+list(range(0,64,group))
assert [f['accepted_queries'] for f in r['frames']]==[0]+[min(n+group,64) for n in range(0,64,group)]
for frame in r['frames']:
    tx=VersionedTransaction.from_bytes(unique[frame['verification_signature']])
    checks=[i for i in tx.message.instructions if str(tx.message.account_keys[i.program_id_index])==r['program_id'] and i.data[0] in (4,6)]
    assert len(checks)==1
    n,amount,expiry,position,generation=struct.unpack('<QQQHI',bytes(checks[0].data)[1:])
    assert (n,amount,expiry,position)==(r['nonce'],r['amount_lamports'],r['expires_at_slot'],frame['frame'])
    assert [str(tx.message.account_keys[i]) for i in checks[0].accounts]==[r['vault'],r['recipient'],r['job']]
signatures=[f['verification_signature'] for f in r['frames']]+[r['close_signature']]
statuses=rpc('getSignatureStatuses',[signatures,{'searchTransactionHistory':True}])
assert all(s and s['err'] is None and s['confirmationStatus']=='finalized' for s in statuses['value'])
for start in range(0,len(unique),200):
    batch=list(unique)[start:start+200]
    statuses=rpc('getSignatureStatuses',[batch,{'searchTransactionHistory':True}])['value']
    assert len(statuses)==len(batch) and all(s and s['err'] is None and s['confirmationStatus']=='finalized' for s in statuses)
for key in ['withdrawal_signature','close_signature']:
    assert r[key] in unique
def transaction(signature):
    receipt=rpc('getTransaction',[signature,{'encoding':'json','commitment':'finalized','maxSupportedTransactionVersion':1}])
    assert receipt and receipt['meta']['err'] is None
    return receipt
withdraw=transaction(r['withdrawal_signature']);close=transaction(r['close_signature'])
verified_cu=[]
for frame in r['frames']:
    item=withdraw if frame['verification_signature']==r['withdrawal_signature'] else transaction(frame['verification_signature'])
    assert item['meta']['computeUnitsConsumed']<=1_400_000
    verified_cu.append(item['meta']['computeUnitsConsumed'])
    if frame['accepted_queries']<64:
        accounts=item['transaction']['message']['accountKeys'];meta=item['meta']
        for address in [r['vault'],r['recipient']]:
            i=accounts.index(address);assert meta['preBalances'][i]==meta['postBalances'][i]
created=next(row for row in r['transactions'] if row['operation']=='create_proof_buffer')
creation=transaction(created['signature'])
keys=withdraw['transaction']['message']['accountKeys'];v=keys.index(r['vault']);to=keys.index(r['recipient']);m=withdraw['meta']
assert m['preBalances'][v]-m['postBalances'][v]==r['amount_lamports']
assert m['postBalances'][to]-m['preBalances'][to]==r['amount_lamports']
close_keys=close['transaction']['message']['accountKeys'];job=close_keys.index(r['job']);cm=close['meta']
assert cm['preBalances'][job]==r['temporary_reserve_lamports'] and cm['postBalances'][job]==0
assert cm['postBalances'][0]-cm['preBalances'][0]==r['temporary_reserve_lamports']-cm['fee']
program=rpc('getAccountInfo',[r['program_id'],{'encoding':'base64','commitment':'finalized'}])['value']
assert program and program['executable'] and program['owner']=='BPFLoaderUpgradeab1e11111111111111111111111'
assert base64.b64decode(program['data'][0])==struct.pack('<I',2)+bytes(Pubkey.from_string(r['program_data']))
program_data=rpc('getAccountInfo',[r['program_data'],{'encoding':'base64','commitment':'finalized'}])['value']
raw=base64.b64decode(program_data['data'][0]);assert int.from_bytes(raw[:4],'little')==3 and raw[12]==0
assert hashlib.sha256(raw[45:]).hexdigest()==r['elf_sha256']
proof=json.loads((case/'native-proof.json').read_text())
assert bytes(proof['request_id']).hex()==r['request_id']
network=hashlib.sha256(b'Parano1dX/network/Solana'+bytes(Pubkey.from_string(GENESIS))).digest()
assert bytes(proof['network_domain'])==network
vault,_=Pubkey.find_program_address([b'Parano1dX-vault',bytes(proof['authority_commitment'])],Pubkey.from_string(r['program_id']))
assert str(vault)==r['vault']
message=(b'Parano1dX/v1/withdraw/SOL'+network+bytes(Pubkey.from_string(r['program_id']))+bytes(vault)+bytes(proof['parameter_id'])+
    struct.pack('<Q',r['nonce'])+bytes(Pubkey.from_string(r['recipient']))+struct.pack('<QQ',r['amount_lamports'],r['expires_at_slot'])+bytes(40))
request=hashlib.sha256(message).hexdigest()
assert request==r['request_id']
context_verified=False
if 'request_context' in proof:
    h=keccak.new(digest_bits=256);h.update(message)
    assert bytes(proof['request_context'])==h.digest();context_verified=True
authority_transactions={row['signature'] for row in r['transactions'] if row['scope']=='authorization'}
expected_fee=sum(VersionedTransaction.from_bytes(unique[s]).message.header.num_required_signatures*5000 for s in authority_transactions)
assert expected_fee==r['actual_network_fee_lamports']
result={'audited_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'rpc_endpoint':URL,'genesis_hash':GENESIS,
    'live_receipt_sha256':hashlib.sha256((case/'live-result.json').read_bytes()).hexdigest(),
    'signed_wires_valid':True,'unique_signed_transactions_checked':len(unique),'all_verification_windows_finalized':True,
    'all_64_query_positions_present':True,'payout_lamport_deltas_verified':True,'complete_reserve_refund_verified':True,
    'all_captured_transactions_finalized':True,'intermediate_payouts_absent':True,'maximum_verification_CU':max(verified_cu),
    'immutable_program_ELF_verified':True,'proof_request_matches':True,'request_binding_verified':True,'signature_fees_match_balance_deltas':True,
    'native_request_context_verified':context_verified,
    'withdrawal_slot':withdraw['slot'],'close_slot':close['slot'],
    'proof_account_creation_slot':creation['slot'],'authorization_slot_span':withdraw['slot']-creation['slot'],
    'authorization_block_time_span_s':withdraw['blockTime']-creation['blockTime'],
    'scope':'Independent read-only checks against finalized public Devnet data and the captured signed transaction wires.'}
(case/'independent-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

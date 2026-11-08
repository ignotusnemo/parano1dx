"""Public Devnet custody and pipelined delivery benchmark.

Uses owner-only research keys outside the source tree. Mainnet is rejected
by its genesis hash. All result files contain public data only.
"""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse,base64,datetime,hashlib,json,os,random,struct,subprocess,sys,threading,time,urllib.request,urllib.error,urllib.parse

parser=argparse.ArgumentParser()
parser.add_argument('python_tools');parser.add_argument('prover');parser.add_argument('wallet_directory')
parser.add_argument('--run',default='normal-1');parser.add_argument('--faults',action='store_true')
parser.add_argument('--send-rate',type=float,default=.9)
parser.add_argument('--tpu-relay')
parser.add_argument('--transaction-version',choices=['legacy','v1'],default='legacy')
parser.add_argument('--chunks-per-transaction',type=int,choices=[1,2,3],default=1)
parser.add_argument('--merge-final-upload',action='store_true')
parser.add_argument('--eager-window',action='store_true')
args=parser.parse_args()
assert args.run.replace('-','').replace('_','').isalnum() and 0<args.send_rate<=8
assert args.transaction_version=='v1' or args.chunks_per_transaction==1
assert not args.merge_final_upload or args.transaction_version=='v1'
assert not args.eager_window or args.transaction_version=='v1' and args.tpu_relay and not args.merge_final_upload
sys.path.insert(0,args.python_tools)
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.transaction import Transaction,VersionedTransaction
from solders.message import MessageV1,TransactionConfig
from solders.instruction import Instruction,AccountMeta
from solders.compute_budget import request_heap_frame,set_compute_unit_limit
from solders.system_program import create_account,CreateAccountParams,transfer,TransferParams,ID as SYSTEM
from tpu_bridge import DirectTpu
from devnet_watch import DevnetWatch

ROOT=Path(__file__).resolve().parent
KEYS=Path(args.wallet_directory).resolve()
CONFIG=json.loads((KEYS/'public-deployment.json').read_text())
CHUNK=int(CONFIG.get('upload_chunk_bytes',960))
assert CHUNK in (960,3584)
assert CHUNK==960 or args.transaction_version=='v1' and args.chunks_per_transaction==1
access_path=KEYS/'rpc-access.json'
ACCESS=json.loads(access_path.read_text()) if access_path.exists() else {}
RPC_URL=ACCESS.get('http_url',CONFIG['rpc_url'])
RPC_PUBLIC=ACCESS.get('public_http_url',CONFIG['rpc_url'])
rpc_secrets=[v for _,v in urllib.parse.parse_qsl(urllib.parse.urlsplit(RPC_URL).query)]
def sanitize(value):
    text=str(value)
    for secret in rpc_secrets:text=text.replace(secret,'[redacted]')
    return text
GENESIS='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'
assert CONFIG['genesis_hash']==GENESIS
RESULTS=ROOT/'results/solana-devnet'/args.run
RESULTS.mkdir(parents=True,exist_ok=False)
lock=threading.Lock();last_send=0.;rpc_id=0;rpc_errors=[];transactions=[];events=[]
def rpc(method,params):
    global last_send,rpc_id
    for attempt in range(5):
        if method=='sendTransaction':
            with lock:
                delay=max(0,last_send+1/args.send_rate-time.monotonic())
                if delay:time.sleep(delay)
                last_send=time.monotonic()
        with lock:rpc_id+=1;ident=rpc_id
        endpoint=ACCESS.get('account_read_url',RPC_URL) if method in ('getAccountInfo','getBalance','getSignatureStatuses','getTransaction','getMinimumBalanceForRentExemption') else RPC_URL
        request=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':ident,'method':method,'params':params}).encode(),
            headers={'Content-Type':'application/json','User-Agent':'Parano1dX-Devnet-research/0.1'})
        try:
            with urllib.request.urlopen(request,timeout=15) as response:body=json.load(response)
            if 'error' in body:raise RuntimeError(sanitize(json.dumps(body['error'])))
            return body['result']
        except urllib.error.HTTPError as error:
            with lock:rpc_errors.append({'method':method,'http_status':error.code,'attempt':attempt+1})
            if error.code not in (429,500,502,503,504) or attempt==4:raise
            time.sleep(float(error.headers.get('Retry-After','2'))+attempt)
        except (TimeoutError,urllib.error.URLError) as error:
            with lock:rpc_errors.append({'method':method,'error':sanitize(error),'attempt':attempt+1})
            if attempt==4:raise
            time.sleep(1+attempt)
assert rpc('getGenesisHash',[])==GENESIS
tpu=DirectTpu(args.tpu_relay,access_path) if args.tpu_relay else None
watcher_init_error=None
try:watcher=DevnetWatch(access_path) if ACCESS.get('websocket_url') else None
except Exception as error:watcher=None;watcher_init_error=type(error).__name__
def key(name):return Keypair.from_bytes(bytes(json.loads((KEYS/(name+'.json')).read_text())))
def fresh_key(name):
    path=KEYS/(args.run+'-'+name+'.json')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    k=Keypair()
    with os.fdopen(fd,'w') as file:json.dump(list(bytes(k)),file)
    return k
payer,second=key('funder'),key('relayer-two')
recipient,job=fresh_key('recipient'),fresh_key('job')
pid=Pubkey.from_string(CONFIG['program_id'])
def account(pubkey,commitment='confirmed'):
    item=rpc('getAccountInfo',[str(pubkey),{'encoding':'base64','commitment':commitment}])
    value=item['value']
    if value:value={**value,'bytes':base64.b64decode(value['data'][0])}
    return value
def balance(pubkey):return rpc('getBalance',[str(pubkey),{'commitment':'confirmed'}])['value']
program=account(pid)
assert program and program['executable']
assert program['owner']=='BPFLoaderUpgradeab1e11111111111111111111111'
assert len(program['bytes'])==36 and int.from_bytes(program['bytes'][:4],'little')==2
program_data=Pubkey.from_bytes(program['bytes'][4:36]);deployed=account(program_data)
assert int.from_bytes(deployed['bytes'][:4],'little')==3 and deployed['bytes'][12]==0
assert hashlib.sha256(deployed['bytes'][45:45+CONFIG['elf_bytes']]).hexdigest()==CONFIG['elf_sha256']
def blockhash():
    value=rpc('getLatestBlockhash',[{'commitment':'confirmed'}])['value'];value['_fetched_at']=time.monotonic();return value
def wait_signature(signature,level='confirmed',timeout=90,record=None):
    start=time.monotonic()
    tag=signature+':'+level
    if watcher:watcher.subscribe({'op':'signature','signature':signature,'level':level,'tag':tag})
    last_poll=0.;last_resend=time.monotonic()
    while time.monotonic()-start<timeout:
        if record is not None and time.monotonic()-last_resend>=1.5:
            rebroadcast(record);last_resend=time.monotonic()
        if watcher:
            event=watcher.wait(tag,.4)
            if event and event.get('event')=='signature':
                if event.get('error'):raise RuntimeError(json.dumps(event['error']))
                if level!='finalized':return event
            if time.monotonic()-last_poll<3:
                time.sleep(.1);continue
        last_poll=time.monotonic()
        result=rpc('getSignatureStatuses',[[signature],{'searchTransactionHistory':True}])['value'][0]
        if result:
            if result['err']:raise RuntimeError(json.dumps({'signature':signature,'error':result['err']}))
            if result['confirmationStatus']=='finalized' or level=='confirmed' and result['confirmationStatus']=='confirmed':return result
        time.sleep(.4)
    raise TimeoutError('Signature confirmation deadline')
def meta(pubkey,write=False,sign=False):return AccountMeta(pubkey,sign,write)
def ix(data,accounts):return Instruction(pid,data,accounts)
def send(instructions,label,scope='authorization',fee=None,signers=None,hash_info=None,cu=25000,wait=False,discard=False,return_record=False,deferred=False):
    sender=fee or payer;info=hash_info or blockhash();began=time.monotonic()
    if time.monotonic()-info.get('_fetched_at',0)>8:info=blockhash()
    if args.transaction_version=='v1':
        config=TransactionConfig(compute_unit_limit=cu,loaded_accounts_data_size_limit=2_097_152,heap_size=262144)
        message=MessageV1.try_compile(sender.pubkey(),instructions,Hash.from_string(info['blockhash']),config)
        tx=VersionedTransaction(message,signers or [sender])
    else:
        tx=Transaction.new_signed_with_payer([request_heap_frame(262144),set_compute_unit_limit(cu)]+instructions,
            sender.pubkey(),signers or [sender],Hash.from_string(info['blockhash']))
    raw=bytes(tx);assert len(raw)<=(4096 if args.transaction_version=='v1' else 1232)
    signature=str(tx.signatures[0])
    transport_result=None
    if deferred:result=signature
    elif tpu:transport_result=tpu.send(raw);result=signature
    else:result=rpc('sendTransaction',[base64.b64encode(raw).decode(),{'encoding':'base64','skipPreflight':True,'maxRetries':3}])
    assert result==signature
    row={'operation':label,'scope':scope,'signature':signature,'transaction_bytes':len(raw),
        'fee_payer':str(sender.pubkey()),'ack_elapsed_s':time.monotonic()-began,'response_discarded':discard,
        'last_valid_block_height':info['lastValidBlockHeight'],'transaction_base64':base64.b64encode(raw).decode(),
        'rebroadcast':False,'transport_receipt':transport_result}
    if deferred:return row
    with lock:
        transactions.append(row)
        with (RESULTS/'transaction-journal.jsonl').open('a') as journal:journal.write(json.dumps(row)+'\n')
    if wait:wait_signature(signature,record=row)
    return row if return_record else signature
def rebroadcast(record):
    began=time.monotonic();raw=base64.b64decode(record['transaction_base64'])
    transport=tpu.send(raw) if tpu else None
    if not tpu:
        signature=rpc('sendTransaction',[record['transaction_base64'],{'encoding':'base64','skipPreflight':True,'maxRetries':3}])
        assert signature==record['signature']
    row={**record,'ack_elapsed_s':time.monotonic()-began,'rebroadcast':True,'response_discarded':False,'transport_receipt':transport}
    with lock:
        transactions.append(row)
        with (RESULTS/'transaction-journal.jsonl').open('a') as journal:journal.write(json.dumps(row)+'\n')
    return row['signature']

def submit_batch(records,repeat=False):
    assert tpu and records
    began=time.monotonic()
    receipt=tpu.send_many([base64.b64decode(row['transaction_base64']) for row in records])
    with lock:
        seen={row['signature'] for row in transactions}
        for record in records:
            row={**record,'ack_elapsed_s':time.monotonic()-began,'transport_receipt':receipt,
                'rebroadcast':record['signature'] in seen,'bitmap_retry_round':repeat,'submission_batch_size':len(records)}
            transactions.append(row)
            seen.add(row['signature'])
            with (RESULTS/'transaction-journal.jsonl').open('a') as journal:journal.write(json.dumps(row)+'\n')

if balance(second.pubkey())<10_000_000:
    send([transfer(TransferParams(from_pubkey=payer.pubkey(),to_pubkey=second.pubkey(),lamports=20_000_000))],
        'fund_independent_relayer',scope='setup',wait=True)
environment={**os.environ,'PARANO1DX_RESEARCH_ROOT_FILE':str(KEYS/'authority-root.bin')}
network=CONFIG['network_domain_hex']
subprocess.run([args.prover,str(RESULTS),'00'*32,network],check=True,env=environment)
proof=json.loads((RESULTS/'native-proof.json').read_text());commitment=bytes(proof['authority_commitment'])
vault,_=Pubkey.find_program_address([b'Parano1dX-vault',commitment],pid)
if account(vault) is None:
    send([ix(bytes([0])+commitment,[meta(payer.pubkey(),True,True),meta(vault,True),meta(SYSTEM)])],
        'initialize_vault',scope='setup',wait=True,cu=100000)
send([transfer(TransferParams(from_pubkey=payer.pubkey(),to_pubkey=vault,lamports=10_000_000))],
    'deposit_native_SOL',scope='setup',wait=True)
vault_before=account(vault);nonce=int.from_bytes(vault_before['bytes'][40:48],'little')
amount=2_500_000;expires=rpc('getSlot',[{'commitment':'confirmed'}])+5000
request=hashlib.sha256(b'Parano1dX/v1/withdraw/SOL'+bytes.fromhex(network)+bytes(pid)+bytes(vault)+
    bytes(proof['parameter_id'])+struct.pack('<Q',nonce)+bytes(recipient.pubkey())+struct.pack('<QQ',amount,expires)+bytes(40)).digest()
fee_balances_before={str(k.pubkey()):balance(k.pubkey()) for k in [payer,second]}
started=time.monotonic();started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
subprocess.run([args.prover,str(RESULTS),request.hex(),network],check=True,env=environment)
subprocess.run([sys.executable,str(ROOT/'evm/prepare.py'),str(RESULTS)],check=True,env={**os.environ,'PYTHONPATH':args.python_tools})
prepared_s=time.monotonic()-started
base=(RESULTS/'stream-base.bin').read_bytes();deltas=[(RESULTS/f'stream-delta-{i:02}.bin').read_bytes() for i in range(64)]
GROUP=5
frames=[(start,bytes([len(deltas[start:start+GROUP])])+b''.join(struct.pack('<H',len(x))+x for x in deltas[start:start+GROUP]))
    for start in range(0,64,GROUP)]
WINDOW=256+9792+7212;capacity=max(len(base),max(len(data) for _,data in frames));space=WINDOW+capacity
reserve=rpc('getMinimumBalanceForRentExemption',[space,{'commitment':'confirmed'}])
send([create_account(CreateAccountParams(from_pubkey=payer.pubkey(),to_pubkey=job.pubkey(),lamports=reserve,space=space,owner=pid)),
    ix(bytes([1])+hashlib.sha256(base).digest()+request+bytes([GROUP]),[meta(job.pubkey(),True,True),meta(payer.pubkey(),False,True)])],
    'create_proof_buffer',signers=[payer,job],wait=True)
if watcher:watcher.subscribe({'op':'account','pubkey':str(job.pubkey()),'level':'confirmed','tag':'job'})
upload_accounts=[meta(job.pubkey(),True),meta(payer.pubkey(),False,True)]
verify_accounts=[meta(vault,True),meta(recipient.pubkey(),True),meta(job.pubkey(),True)]
def job_state(force_http=False):
    if watcher and not force_http:
        with watcher.condition:event=watcher.values.get('job')
        if event and event.get('header_base64'):return base64.b64decode(event['header_base64'])
    value=rpc('getAccountInfo',[str(job.pubkey()),{'encoding':'base64','commitment':'confirmed','dataSlice':{'offset':0,'length':256}}])['value']
    assert value
    return base64.b64decode(value['data'][0])
frame_records=[];hot_info=None
for frame,payload in [(65535,base)]+frames:
    if args.eager_window:
        frame_start=time.monotonic();epoch=0
        if hot_info is None or time.monotonic()-hot_info['_fetched_at']>6:hot_info=blockhash()
        packets=[]
        for offset in range(0,len(payload),CHUNK):
            instructions=[ix(bytes([2])+struct.pack('<HHII',frame,len(payload),epoch,offset)+payload[offset:offset+CHUNK],upload_accounts),
                ix(bytes([6])+struct.pack('<QQQHI',nonce,amount,expires,frame,epoch),verify_accounts)]
            packet=send(instructions,'upload_with_completion_probe',hash_info=hot_info,cu=1_400_000,deferred=True)
            packet['upload_offset']=offset;packets.append(packet)
        inject=args.faults and frame==15
        delivered=list(packets)
        if inject:random.Random(701).shuffle(delivered)
        dropped=delivered.pop(len(delivered)//2) if inject else None
        submit_batch(delivered)
        if inject:events.append({'case':'reordered_window_batch_with_lost_packet','frame':frame,'dropped_offset':dropped['upload_offset']})
        accepted=0 if frame==65535 else min(64,frame+GROUP)
        last_retry=time.monotonic();retries=0;deadline=last_retry+90
        while True:
            state=job_state(False)
            if state[8] in (1,2) and int.from_bytes(state[113:121],'little')==accepted and int.from_bytes(state[9:13],'little')==0:break
            assert int.from_bytes(state[129:133],'little')==epoch
            if time.monotonic()>deadline:raise TimeoutError('Eager window completion deadline')
            if time.monotonic()-last_retry>=1.2:
                state=job_state(True)
                if state[8] in (1,2) and int.from_bytes(state[113:121],'little')==accepted and int.from_bytes(state[9:13],'little')==0:break
                mask=int.from_bytes(state[121:129],'little')
                missing=[row for row in packets if not mask&(1<<(row['upload_offset']//CHUNK))]
                if missing:
                    submit_batch(missing,repeat=True);retries+=1
                    if inject:events.append({'case':'bitmap_resume_missing_chunks_only','frame':frame,'missing_offsets':[row['upload_offset'] for row in missing]})
                last_retry=time.monotonic()
            if watcher:
                with watcher.condition:watcher.condition.wait(timeout=.08)
            else:time.sleep(.15)
        frame_records.append({'frame':frame,'accepted_queries':accepted,'payload_bytes':len(payload),
            'delivery_and_confirmed_verification_s':time.monotonic()-frame_start,'verification_signature':None,
            'verification_candidate_signatures':[row['signature'] for row in packets],'retry_rounds':retries})
        print(json.dumps({'frame':frame,'accepted_queries':accepted,'elapsed_s':round(time.monotonic()-started,3)}),flush=True)
        continue
    frame_start=time.monotonic();state=job_state(True);epoch=int.from_bytes(state[129:133],'little')
    offsets=list(range(0,len(payload),CHUNK));expected_mask=(1<<len(offsets))-1
    inject=args.faults and frame==15
    if inject:random.Random(701).shuffle(offsets)
    held=offsets[-args.chunks_per_transaction:] if args.merge_final_upload else []
    if held:
        offsets=offsets[:-len(held)]
        expected_mask^=sum(1<<(offset//CHUNK) for offset in held)
    dropped=offsets.pop(len(offsets)//2) if inject else None
    info=blockhash()
    upload_cache={}
    def bundles(offsets):
        return [tuple(offsets[i:i+args.chunks_per_transaction]) for i in range(0,len(offsets),args.chunks_per_transaction)]
    def upload(offsets,info,discard=False,current_height=None):
        cached=upload_cache.get(offsets)
        if cached and current_height is not None and current_height<=cached['last_valid_block_height']:
            return rebroadcast(cached)
        instructions=[ix(bytes([2])+struct.pack('<HHII',frame,len(payload),epoch,offset)+payload[offset:offset+CHUNK],upload_accounts) for offset in offsets]
        row=send(instructions,'upload',hash_info=info,discard=discard,return_record=True,cu=25000*len(offsets))
        upload_cache[offsets]=row
        return row['signature']
    with ThreadPoolExecutor(4) as pool:
        futures=[pool.submit(upload,batch,info,inject and i==0) for i,batch in enumerate(bundles(offsets))]
        for future in futures:future.result()
    if inject:
        events.append({'case':'reordered_concurrent_delivery_and_response_loss','frame':frame,'dropped_offset':dropped})
    retry_round=0;deadline=time.monotonic()+90
    while True:
        state=job_state(retry_round>0);mask=int.from_bytes(state[121:129],'little')
        assert int.from_bytes(state[129:133],'little')==epoch
        expected_received=len(payload)-sum(min(CHUNK,len(payload)-o) for o in held)
        if mask==expected_mask and int.from_bytes(state[9:13],'little')==expected_received:break
        if time.monotonic()>deadline:raise TimeoutError('Window delivery deadline')
        missing=[offset for offset in range(0,len(payload),CHUNK) if offset not in held and not mask&(1<<(offset//CHUNK))]
        time.sleep(.6)
        state=job_state(True);mask=int.from_bytes(state[121:129],'little')
        missing=[offset for offset in missing if not mask&(1<<(offset//CHUNK))]
        if not missing:continue
        retry_round+=1
        if retry_round>4:raise RuntimeError('Window retry budget exceeded')
        info=blockhash()
        height=rpc('getBlockHeight',[{'commitment':'confirmed'}])
        with ThreadPoolExecutor(4) as pool:
            for future in [pool.submit(upload,batch,info,False,height) for batch in bundles(missing)]:future.result()
        if inject:events.append({'case':'bitmap_resume_missing_chunks_only','frame':frame,'missing_offsets':missing})
        time.sleep(.5)
    fee=second if frame!=65535 and (frame//GROUP)%2 else payer
    final_uploads=[ix(bytes([2])+struct.pack('<HHII',frame,len(payload),epoch,o)+payload[o:o+CHUNK],upload_accounts) for o in held]
    verify_sig=send(final_uploads+[ix(bytes([4])+struct.pack('<QQQHI',nonce,amount,expires,frame,epoch),verify_accounts)],
        'prepare_transcript' if frame==65535 else 'verify_query_batch',fee=fee,
        signers=[payer,second] if held and fee==second else None,cu=1_400_000,wait=True)
    accepted=0 if frame==65535 else min(64,frame+GROUP)
    for _ in range(20):
        state=job_state(True)
        if int.from_bytes(state[113:121],'little')==accepted and state[8] in (1,2) and int.from_bytes(state[9:13],'little')==0:break
        time.sleep(.4)
    else:raise TimeoutError('Confirmed progress read lag')
    frame_records.append({'frame':frame,'accepted_queries':accepted,'payload_bytes':len(payload),
        'delivery_and_confirmed_verification_s':time.monotonic()-frame_start,'verification_signature':verify_sig,'retry_rounds':retry_round})
    print(json.dumps({'frame':frame,'accepted_queries':accepted,'elapsed_s':round(time.monotonic()-started,3)}),flush=True)
confirmed_s=time.monotonic()-started
assert balance(recipient.pubkey())==amount
assert account(vault)['lamports']==vault_before['lamports']-amount
assert int.from_bytes(account(vault)['bytes'][40:48],'little')==nonce+1
ledger_order=None
def eager_verifier_signature(frame):
    global ledger_order
    if ledger_order is None:
        ledger_order=[row['signature'] for row in rpc('getSignaturesForAddress',[str(job.pubkey()),{'limit':1000,'commitment':'confirmed'}]) if row['err'] is None]
    candidates=frame['verification_candidate_signatures']
    ordered=[sig for sig in ledger_order if sig in candidates]+[sig for sig in candidates if sig not in ledger_order]
    for signature in ordered:
        receipt=rpc('getTransaction',[signature,{'encoding':'json','commitment':'confirmed','maxSupportedTransactionVersion':1}])
        if receipt and receipt['meta']['err'] is None and receipt['meta']['computeUnitsConsumed']>100000:return signature
    raise RuntimeError('Finalizing window transaction not found')
if args.eager_window:
    verify_sig=eager_verifier_signature(frame_records[-1]);frame_records[-1]['verification_signature']=verify_sig
close_sig=send([ix(bytes([5]),[meta(job.pubkey(),True),meta(payer.pubkey(),True,True)])],'close_proof_buffer',wait=True)
assert account(job.pubkey()) is None
wait_signature(verify_sig,'finalized');finalized_s=time.monotonic()-started
wait_signature(close_sig,'finalized');fully_closed_s=time.monotonic()-started
fee_balances_after={str(k.pubkey()):balance(k.pubkey()) for k in [payer,second]}
actual_network_fee=sum(fee_balances_before.values())-sum(fee_balances_after.values())
verification_receipts=[]
for frame in frame_records:
    if frame['verification_signature'] is None:frame['verification_signature']=eager_verifier_signature(frame)
    receipt=rpc('getTransaction',[frame['verification_signature'],{'encoding':'json','commitment':'finalized','maxSupportedTransactionVersion':1}])
    assert receipt and receipt['meta']['err'] is None
    if frame['accepted_queries']<64:
        keys=receipt['transaction']['message']['accountKeys'];m=receipt['meta']
        for key in [vault,recipient.pubkey()]:
            i=keys.index(str(key));assert m['postBalances'][i]==m['preBalances'][i]
    verification_receipts.append({'signature':frame['verification_signature'],'slot':receipt['slot'],'block_time':receipt['blockTime'],
        'compute_units':receipt['meta']['computeUnitsConsumed'],'fee_lamports':receipt['meta']['fee'],'logs':receipt['meta']['logMessages']})
    time.sleep(.15)
result={'network':'Solana Devnet','genesis_hash':GENESIS,'rpc_endpoint':RPC_PUBLIC,'account_read_endpoint':ACCESS.get('account_read_url',RPC_PUBLIC),'rpc_provider':ACCESS.get('provider','Public RPC'),'real_assets_used':False,
    'transaction_version':args.transaction_version,'chunks_per_upload_transaction':args.chunks_per_transaction,'upload_chunk_bytes':CHUNK,
    'final_upload_and_verification_merged':args.merge_final_upload,'intermediate_payouts_checked_in_receipts':True,
    'eager_window_completion_probes':args.eager_window,
    'packet_size_limit':4096 if args.transaction_version=='v1' else 1232,
    'program_id':str(pid),'program_data':str(program_data),'program_immutable_verified':True,'elf_sha256':CONFIG['elf_sha256'],
    'vault':str(vault),'recipient':str(recipient.pubkey()),'job':str(job.pubkey()),'request_id':request.hex(),
    'nonce':nonce,'amount_lamports':amount,'expires_at_slot':expires,'started_at_utc':started_utc,
    'proof_root_source':'owner-only private research file','proof_preparation_s':prepared_s,'query_batch_size':GROUP,
    'ordered_verification_windows':len(frame_records),'authorization_transactions_submitted':sum(t['scope']=='authorization' for t in transactions),
    'unique_authorization_transactions':len({t['signature'] for t in transactions if t['scope']=='authorization'}),
    'rebroadcast_submissions':sum(t.get('rebroadcast',False) for t in transactions if t['scope']=='authorization'),
    'send_rate_limit_per_s':None if tpu else args.send_rate,'concurrent_upload_workers':4,'temporary_account_bytes':space,
    'transaction_transport':'direct validator TPU QUIC' if tpu else 'RPC sendTransaction',
    'rpc_send_quota_applies_to_payload':not bool(tpu),'websocket_events_received':watcher.events if watcher else 0,
    'http_confirmation_endpoint':ACCESS.get('account_read_url',RPC_PUBLIC),
    'temporary_reserve_lamports':reserve,'reserve_refunded':True,'withdrawal_confirmed_s':confirmed_s,
    'delivery_to_withdrawal_confirmed_s':confirmed_s-prepared_s,'websocket_initialization_error':watcher_init_error,
    'withdrawal_finalized_s':finalized_s,'reserve_refund_finalized_s':fully_closed_s,
    'withdrawal_signature':verify_sig,'close_signature':close_sig,'payout_and_nonce_checked':True,
    'actual_network_fee_lamports':actual_network_fee,'fee_payer_balances_before':fee_balances_before,'fee_payer_balances_after':fee_balances_after,
    'verification_receipts':verification_receipts,'measurement_host':'research relayer host',
    'fault_injection_enabled':args.faults,'fault_events':events,'rpc_retries':rpc_errors,'frames':frame_records,'transactions':transactions,
    'scope':'Complete live Devnet authorization from the recorded research relayer host. The timer includes proof preparation, temporary-account creation, delivery and observed confirmation. Setup and program deployment precede the timer. Finality is Devnet finality.'}
(RESULTS/'live-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('transactions','frames')},indent=2),flush=True)
if watcher:watcher.close()
if tpu:tpu.close()

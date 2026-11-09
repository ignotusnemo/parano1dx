"""Resumable, rate-limited Devnet deployment of the measured SBF program.

Upgradeable-loader encodings follow the pinned solana-loader-v3-interface
SDK. The program is frozen only after its deployed ELF is checked.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import base64,hashlib,json,os,struct,sys,threading,time,urllib.request,urllib.error,urllib.parse
sys.path.insert(0,sys.argv[1])
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solders.instruction import Instruction,AccountMeta
from solders.transaction import Transaction,VersionedTransaction
from solders.message import MessageV1,TransactionConfig
from solders.system_program import create_account,CreateAccountParams,ID as SYSTEM
from solders.compute_budget import set_compute_unit_limit
from solders.sysvar import RENT,CLOCK
from tpu_bridge import DirectTpu
KEYS=Path(sys.argv[2]);ELF_PATH=Path(sys.argv[3]);ELF=ELF_PATH.read_bytes()
C=json.loads((KEYS/'public-deployment.json').read_text())
V1=C.get('deployment_transaction_version')==1
# The current loader rejects a 3584-byte Write instruction. Keep its bounded
# bincode input separate from the application's larger raw-slice transport.
WRITE=900
access_path=KEYS/'rpc-access.json'
access=json.loads(access_path.read_text()) if access_path.exists() else {}
RPC_URL=access.get('http_url',C['rpc_url'])
rpc_secrets=[v for _,v in urllib.parse.parse_qsl(urllib.parse.urlsplit(RPC_URL).query)]
def sanitize(value):
    text=str(value)
    for secret in rpc_secrets:text=text.replace(secret,'[redacted]')
    return text
assert C['genesis_hash']=='EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'
assert len(ELF)==C['elf_bytes'] and hashlib.sha256(ELF).hexdigest()==C['elf_sha256']
validation=json.loads(Path(str(ELF_PATH)+'.validation.json').read_text())
assert validation['network_domain_hex']==C['network_domain_hex'], 'Validated network domain differs from the deployment manifest'
assert validation['program_elf_sha256']==C['elf_sha256'] and validation['positive_lifecycle_completed']
loader=Pubkey.from_string('BPFLoaderUpgradeab1e11111111111111111111111')
def key(name):return Keypair.from_bytes(bytes(json.loads((KEYS/(name+'.json')).read_text())))
payer,program,buffer=key('funder'),key('program'),key('buffer')
program_data,_=Pubkey.find_program_address([bytes(program.pubkey())],loader)
limiter=threading.Lock();preflight_lock=threading.Lock();preflight_done=set();last_call=0.;last_send=0.;records=[]
def rpc(method,params):
    global last_call,last_send
    for attempt in range(7):
        with limiter:
            delay=max(0,last_call+(.15 if access else .4)-time.monotonic())
            if delay:time.sleep(delay)
            last_call=time.monotonic()
            if method=='sendTransaction':
                delay=max(0,last_send+1/access.get('send_rate_limit_per_s',.9)-time.monotonic())
                if delay:time.sleep(delay)
                last_send=time.monotonic()
        endpoint=access.get('account_read_url',RPC_URL) if method=='getAccountInfo' else RPC_URL
        req=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),
            headers={'Content-Type':'application/json','User-Agent':'Parano1dX-Devnet-research/0.1'})
        try:
            with urllib.request.urlopen(req,timeout=12) as response:body=json.load(response)
            if 'error' in body:raise RuntimeError(sanitize(json.dumps(body['error'])))
            return body['result']
        except urllib.error.HTTPError as e:
            if e.code not in (429,500,502,503,504) or attempt==6:raise
            print(json.dumps({'rpc_retry_http':e.code,'method':method,'attempt':attempt+1}),flush=True)
            time.sleep(float(e.headers.get('Retry-After','5'))+attempt)
        except (TimeoutError,urllib.error.URLError) as e:
            if attempt==6:raise
            print(json.dumps({'rpc_retry_transport':sanitize(e),'method':method,'attempt':attempt+1}),flush=True)
            time.sleep(2+attempt)
assert rpc('getGenesisHash',[])==C['genesis_hash']
tpu=DirectTpu(sys.argv[4],access_path) if len(sys.argv)>4 else None
if tpu:print(json.dumps({'transport':'direct validator TPU QUIC','ready':True}),flush=True)
def account(pubkey):
    value=rpc('getAccountInfo',[str(pubkey),{'encoding':'base64','commitment':'confirmed'}])['value']
    if value:value={**value,'bytes':base64.b64decode(value['data'][0])}
    return value
def rent(size):return rpc('getMinimumBalanceForRentExemption',[size,{'commitment':'confirmed'}])
def recent():
    value=rpc('getLatestBlockhash',[{'commitment':'confirmed'}])['value'];value['_fetched_at']=time.monotonic();return value
def meta(pubkey,write=False,sign=False):return AccountMeta(pubkey,sign,write)
def wait(sig,raw):
    start=time.monotonic()
    last_resend=start
    while time.monotonic()-start<90:
        if tpu and time.monotonic()-last_resend>=1.5:tpu.send(raw);last_resend=time.monotonic()
        s=rpc('getSignatureStatuses',[[sig],{'searchTransactionHistory':True}])['value'][0]
        if s:
            if s['err']:raise RuntimeError(json.dumps(s['err']))
            if s['confirmationStatus'] in ('confirmed','finalized'):return
        time.sleep(.4)
    raise TimeoutError('Deployment transaction confirmation')
def send(instructions,label,signers=None,hash_info=None,cu=25000,confirm=True):
    info=hash_info or recent()
    if time.monotonic()-info.get('_fetched_at',0)>8:info=recent()
    if V1:
        message=MessageV1.try_compile(payer.pubkey(),instructions,Hash.from_string(info['blockhash']),
            TransactionConfig(compute_unit_limit=cu,loaded_accounts_data_size_limit=2097152))
        tx=VersionedTransaction(message,signers or [payer])
    else:tx=Transaction.new_signed_with_payer([set_compute_unit_limit(cu)]+instructions,payer.pubkey(),signers or [payer],Hash.from_string(info['blockhash']))
    raw=bytes(tx);assert len(raw)<=(4096 if V1 else 1232)
    if tpu:
        shape=(label,len(instructions),max(len(i.data) for i in instructions),V1)
        with preflight_lock:
            if shape not in preflight_done:
                simulation=rpc('simulateTransaction',[base64.b64encode(raw).decode(),{'encoding':'base64','commitment':'confirmed','sigVerify':True}])['value']
                if simulation['err']:raise RuntimeError(json.dumps({'preflight_rejected':label,'error':simulation['err'],'logs':simulation.get('logs',[])[-3:]}))
                preflight_done.add(shape)
    if tpu:tpu.send(raw);sig=str(tx.signatures[0])
    else:sig=rpc('sendTransaction',[base64.b64encode(raw).decode(),{'encoding':'base64','skipPreflight':False,'maxRetries':2}])
    assert sig==str(tx.signatures[0]);records.append({'operation':label,'signature':sig,'transaction_bytes':len(raw)})
    with (KEYS/'deployment-journal.jsonl').open('a') as journal:
        journal.write(json.dumps(records[-1])+'\n')
    if confirm:wait(sig,raw)
    return sig

deployed=account(program.pubkey())
if not (deployed and deployed['executable']):
    state=account(buffer.pubkey())
    if state is None:
        try:
            send([create_account(CreateAccountParams(from_pubkey=payer.pubkey(),to_pubkey=buffer.pubkey(),
                lamports=rent(37+len(ELF)),space=37+len(ELF),owner=loader)),
                Instruction(loader,struct.pack('<I',0),[meta(buffer.pubkey(),True),meta(payer.pubkey())])],
                'initialize_buffer',signers=[payer,buffer])
        except RuntimeError:
            state=account(buffer.pubkey())
            if not state:raise
            print(json.dumps({'resumed_existing_buffer':True}),flush=True)
    for round_no in range(12):
        state=account(buffer.pubkey());assert state and state['owner']==str(loader)
        assert state['bytes'][:5]==struct.pack('<I',1)+bytes([1]) and state['bytes'][5:37]==bytes(payer.pubkey())
        current=state['bytes'][37:]
        missing=[offset for offset in range(0,len(ELF),WRITE) if current[offset:offset+WRITE]!=ELF[offset:offset+WRITE]]
        print(json.dumps({'deployment_round':round_no,'missing_chunks':len(missing),'total_chunks':(len(ELF)+WRITE-1)//WRITE}),flush=True)
        if not missing:break
        for start in range(0,len(missing),35):
            info=recent()
            def upload(offset):
                chunk=ELF[offset:offset+WRITE]
                data=struct.pack('<IIQ',1,offset,len(chunk))+chunk
                return send([Instruction(loader,data,[meta(buffer.pubkey(),True),meta(payer.pubkey(),False,True)])],
                    'write_buffer',hash_info=info,confirm=False,cu=100000 if V1 else 25000)
            with ThreadPoolExecutor(3) as pool:
                for future in [pool.submit(upload,offset) for offset in missing[start:start+35]]:future.result()
            print(json.dumps({'submitted_remaining_chunks':min(start+35,len(missing)),'of':len(missing)}),flush=True)
        time.sleep(2)
    else:raise RuntimeError('Deployment retry budget exceeded')
    state=account(buffer.pubkey());assert state['bytes'][37:37+len(ELF)]==ELF
    existing=account(program.pubkey());instructions=[];signers=[payer]
    if existing is None:
        instructions.append(create_account(CreateAccountParams(from_pubkey=payer.pubkey(),to_pubkey=program.pubkey(),
            lamports=rent(36),space=36,owner=loader)));signers.append(program)
    else:assert existing['owner']==str(loader) and existing['bytes'][:4]==bytes(4)
    instructions.append(Instruction(loader,struct.pack('<IQ',2,len(ELF)),[
        meta(payer.pubkey(),True,True),meta(program_data,True),meta(program.pubkey(),True),meta(buffer.pubkey(),True),
        meta(RENT),meta(CLOCK),meta(SYSTEM),meta(payer.pubkey(),False,True)]))
    send(instructions,'deploy_program',signers=signers,cu=1_400_000)
deployed=account(program.pubkey());state=account(program_data)
assert deployed and deployed['executable'] and deployed['owner']==str(loader)
assert deployed['bytes']==struct.pack('<I',2)+bytes(program_data)
assert int.from_bytes(state['bytes'][:4],'little')==3
assert hashlib.sha256(state['bytes'][45:45+len(ELF)]).hexdigest()==C['elf_sha256']
if state['bytes'][12]!=0:
    assert state['bytes'][12]==1 and state['bytes'][13:45]==bytes(payer.pubkey())
    send([Instruction(loader,struct.pack('<I',4),[meta(program_data,True),meta(payer.pubkey(),False,True)])],'freeze_program')
state=account(program_data);assert state['bytes'][12]==0
result={'network':'Solana Devnet','genesis_hash':C['genesis_hash'],'program_id':str(program.pubkey()),
    'program_data':str(program_data),'elf_sha256':C['elf_sha256'],'elf_bytes':len(ELF),
    'immutable_verified':True,'real_assets_used':False,'transport':'direct TPU QUIC' if tpu else 'RPC',
    'records':records}
(KEYS/'deployment-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='records'},indent=2),flush=True)
if tpu:tpu.close()

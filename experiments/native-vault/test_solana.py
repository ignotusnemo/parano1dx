"""Signed local Solana streaming withdrawal and relayer-recovery checks.

Usage: python3 test_solana.py PYTHON_TOOLS PROGRAM_SO NATIVE_PROVER
All seeds are public fixtures. This harness contacts no RPC endpoint.
"""
from pathlib import Path
import base64,hashlib,json,os,struct,subprocess,sys,time
sys.path.insert(0,sys.argv[1])
from solders.litesvm import LiteSVM
from solders.keypair import Keypair
from solders.account import Account
from solders.pubkey import Pubkey
from solders.instruction import Instruction,AccountMeta
from solders.system_program import create_account,CreateAccountParams,transfer,TransferParams,ID as SYSTEM
from solders.transaction import Transaction,VersionedTransaction
from solders.message import MessageV1,TransactionConfig
from solders.transaction_metadata import FailedTransactionMetadata
from solders.compute_budget import request_heap_frame,set_compute_unit_limit
import solders

ROOT=Path(__file__).resolve().parent
def option(name,default):return sys.argv[sys.argv.index(name)+1] if name in sys.argv else default
RESULTS=Path(option('--fixture-directory',str(ROOT/'results'))).resolve()
GROUP=int(option('--group-size','5'))
assert 1<=GROUP<=5
OUTPUT=Path(option('--output-directory',str(RESULTS)))
OUTPUT.mkdir(parents=True,exist_ok=True)
REUSE='--reuse-fixture' in sys.argv
V1='--v1' in sys.argv
EAGER='--eager-window' in sys.argv
assert not EAGER or V1
CHUNK=int(option('--chunk-bytes','960'))
assert CHUNK in (960,3584) and (CHUNK==960 or V1)
PACK=3 if V1 and CHUNK==960 else 1
metadata=json.loads((RESULTS/'native-proof.json').read_text())
payer=Keypair.from_seed(bytes([31])*32)
second_payer=Keypair.from_seed(bytes([32])*32)
pid=Keypair.from_seed(bytes([77])*32).pubkey()
recipient=Keypair.from_seed(bytes([89])*32).pubkey()
job_key=Keypair.from_seed(bytes([91])*32)
commitment=bytes(metadata['authority_commitment'])
vault,bump=Pubkey.find_program_address([b'Parano1dX-vault',commitment],pid)
network=b'Parano1dX local Solana research1'
parameters=bytes(metadata['parameter_id'])
nonce,amount,expires=0,250_000_000,100_000
request=hashlib.sha256(b'Parano1dX/v1/withdraw/SOL'+network+bytes(pid)+bytes(vault)+parameters+
    struct.pack('<Q',nonce)+bytes(recipient)+struct.pack('<QQ',amount,expires)+bytes(32)+bytes(8)).digest()
prover_fixture_wall_ms=transport_expansion_ms=0.
if not REUSE:
    start=time.perf_counter()
    subprocess.run([sys.argv[3],str(RESULTS),request.hex()],check=True)
    prover_fixture_wall_ms=(time.perf_counter()-start)*1000
    start=time.perf_counter()
    subprocess.run([sys.executable,str(ROOT/'evm/prepare.py'),str(RESULTS)],check=True,
        env={**os.environ,'PYTHONPATH':sys.argv[1]})
    transport_expansion_ms=(time.perf_counter()-start)*1000
native_check=subprocess.run([sys.argv[3],'--check-stream',str(RESULTS)],check=True,capture_output=True,text=True)
stream_check=json.loads(native_check.stdout)
(OUTPUT/'stream-native-check.json').write_text(json.dumps(stream_check,indent=2)+'\n')
metadata=json.loads((RESULTS/'native-proof.json').read_text())
assert bytes(metadata['request_id'])==request
base=(RESULTS/'stream-base.bin').read_bytes()
queries=[(RESULTS/f'stream-delta-{i:02}.bin').read_bytes() for i in range(64)]
frames=[(start,bytes([len(queries[start:start+GROUP])])+b''.join(struct.pack('<H',len(q))+q for q in queries[start:start+GROUP]))
        for start in range(0,64,GROUP)]
HEADER,CACHE,BASE_FRAME=256,9792,65535
PREVIOUS=HEADER+CACHE
WINDOW=PREVIOUS+7212
capacity=max(len(base),max(len(data) for _,data in frames))
space=WINDOW+capacity
assert len(base)==9232 and all(12<=len(q)<=7224 for q in queries)
svm=LiteSVM()
svm.airdrop(payer.pubkey(),100_000_000_000)
svm.airdrop(second_payer.pubkey(),1_000_000_000)
clock=svm.get_clock();clock.slot=1;svm.set_clock(clock)
svm.add_program_from_file(pid,Path(sys.argv[2]).resolve())
svm.set_account(recipient,Account(10_000_000,bytes(64),pid))
records=[]
recovery_events=[]
def meta(key,write=False,sign=False):return AccountMeta(key,sign,write)
def ix(data,accounts):return Instruction(pid,data,accounts)
def send(name,instructions,signers=None,expect_success=True,fee_payer=None,scope='authorization',cu=1_400_000):
    sender=fee_payer or payer
    start=time.perf_counter();svm.expire_blockhash()
    if V1:
        message=MessageV1.try_compile(sender.pubkey(),instructions,svm.latest_blockhash(),
            TransactionConfig(compute_unit_limit=cu,loaded_accounts_data_size_limit=2097152,heap_size=262144))
        tx=VersionedTransaction(message,signers or [sender])
    else:
        tx=Transaction.new_signed_with_payer([request_heap_frame(262_144),set_compute_unit_limit(cu)]+instructions,
            sender.pubkey(),signers or [sender],svm.latest_blockhash())
    assert len(bytes(tx))<=(4096 if V1 else 1232),(name,len(bytes(tx)))
    before=svm.get_balance(sender.pubkey());submit=time.perf_counter()
    if V1:
        # This LiteSVM build decodes v1 but drops its inline resource config.
        # Check its signed wire, then execute the identical instructions with
        # the same limits expressed in the emulator's supported legacy form.
        VersionedTransaction.from_bytes(bytes(tx)).verify_and_hash_message()
        replay=Transaction.new_signed_with_payer([request_heap_frame(262144),set_compute_unit_limit(cu)]+instructions,
            sender.pubkey(),signers or [sender],svm.latest_blockhash())
        outcome=svm.send_transaction(replay)
    else:outcome=svm.send_transaction(tx)
    end=time.perf_counter()
    failed=isinstance(outcome,FailedTransactionMetadata);m=outcome.meta() if failed else outcome
    row={'operation':name,'scope':scope,'success':not failed,'compute_units':m.compute_units_consumed(),
         'signature':str(tx.signatures[0]),'transaction_base64':base64.b64encode(bytes(tx)).decode(),
         'requested_compute_units':cu,'transaction_bytes':len(bytes(tx)),
         'payer_lamport_delta':before-svm.get_balance(sender.pubkey()),'fee_payer':str(sender.pubkey()),
         'local_transaction_wall_ms':(end-start)*1000,'local_vm_submit_ms':(end-submit)*1000,
         'error':str(outcome.err()) if failed else None,'logs':m.logs()}
    records.append(row)
    if failed==expect_success:
        (OUTPUT/'solana-attempt.json').write_text(json.dumps({'records':records},indent=2)+'\n')
        raise RuntimeError(json.dumps(row,indent=2))
    if name!='upload':print(json.dumps({k:v for k,v in row.items() if k!='logs'}),flush=True)
    return row

send('initialize_vault',[ix(bytes([0])+commitment,[meta(payer.pubkey(),True,True),meta(vault,True),meta(SYSTEM)])],scope='setup')
send('deposit_native_SOL',[transfer(TransferParams(from_pubkey=payer.pubkey(),to_pubkey=vault,lamports=1_000_000_000))],scope='setup',cu=25000)
rent=svm.minimum_balance_for_rent_exemption(space)
send('create_proof_buffer',[
    create_account(CreateAccountParams(from_pubkey=payer.pubkey(),to_pubkey=job_key.pubkey(),lamports=rent,space=space,owner=pid)),
    ix(bytes([1])+hashlib.sha256(base).digest()+request+bytes([GROUP]),[meta(job_key.pubkey(),True,True),meta(payer.pubkey(),False,True)])],
    signers=[payer,job_key],cu=25000)
snapshot=lambda:(svm.get_balance(vault) or 0,svm.get_balance(recipient) or 0,bytes(svm.get_account(vault).data))
before=snapshot()
withdraw_accounts=[meta(vault,True),meta(recipient,True),meta(job_key.pubkey(),True)]
upload_accounts=[meta(job_key.pubkey(),True),meta(payer.pubkey(),False,True)]
def epoch():return int.from_bytes(bytes(svm.get_account(job_key.pubkey()).data)[129:133],'little')
def verify(frame,n=nonce,a=amount,e=expires,accounts=None,maybe=False):
    return ix(bytes([6 if maybe else 4])+struct.pack('<QQQHI',n,a,e,frame,epoch()),accounts or withdraw_accounts)
def upload(frame,offset,data,total,generation=None):
    return ix(bytes([2])+struct.pack('<HHII',frame,total,epoch() if generation is None else generation,offset)+data,upload_accounts)
def reset(frame):
    send('reset_current_window',[ix(bytes([3])+struct.pack('<HI',frame,epoch()),upload_accounts)],scope='adversarial',cu=25000)
def transfer_frame(frame,data,scope='authorization',verify_success=True,restart=False):
    account=bytes(svm.get_account(job_key.pubkey()).data)
    mask=int.from_bytes(account[121:129],'little')
    offsets=[offset for offset in range(0,len(data),CHUNK) if not mask&(1<<(offset//CHUNK))]
    if restart:offsets.reverse()
    attempted_verification=False
    for begin in range(0,len(offsets),PACK):
        bundle=offsets[begin:begin+PACK];offset=bundle[0]
        end=min(offset+CHUNK,len(data))
        instructions=[upload(frame,o,data[o:o+CHUNK],len(data)) for o in bundle]
        final=begin+PACK>=len(offsets) if V1 else end==len(data) and end-offset<=768
        if final or EAGER:instructions.append(verify(frame,maybe=restart or EAGER))
        alternate=final and frame!=BASE_FRAME and (frame//GROUP)%2==1
        signer=[payer,second_payer] if alternate else [payer]
        row=send('upload_with_completion_probe' if final and restart else 'prepare_transcript' if final and frame==BASE_FRAME else 'verify_query' if final else 'upload',instructions,
            scope=scope,expect_success=verify_success if final and not restart else True,
            fee_payer=second_payer if alternate else payer,signers=signer,
            cu=1_400_000 if final or EAGER else 25000*len(bundle))
        if final:attempted_verification=True
        if restart and offset==offsets[0]:
            # The last-position packet arrives first. Simulate a lost RPC
            # response and resume from the persisted bitmap after restart.
            state=bytes(svm.get_account(job_key.pubkey()).data)
            recovered=int.from_bytes(state[121:129],'little')
            assert recovered&(1<<(offset//CHUNK)) and int.from_bytes(state[113:121],'little')==frame
            recovery_events.append({'case':'restart_after_reordered_upload_response_loss','frame':frame,'resumed_bitmap':recovered})
    state=bytes(svm.get_account(job_key.pubkey()).data)
    pending=state[8]==(0 if frame==BASE_FRAME else 1) and (frame==BASE_FRAME or int.from_bytes(state[113:121],'little')==frame)
    if pending and (restart or not attempted_verification):
        row=send('prepare_transcript' if frame==BASE_FRAME else 'verify_query',[verify(frame)],scope=scope,
            expect_success=verify_success,fee_payer=second_payer if frame!=BASE_FRAME and (frame//GROUP)%2 else payer,cu=1_400_000)
    return row

send('incomplete_base_rejected',[verify(BASE_FRAME)],expect_success=False,scope='adversarial')
send('out_of_order_upload_accepted',[upload(BASE_FRAME,CHUNK,base[CHUNK:(2*CHUNK)],len(base))],scope='adversarial',cu=25000)
state=bytes(svm.get_account(job_key.pubkey()).data)
send('identical_duplicate_is_idempotent',[upload(BASE_FRAME,CHUNK,base[CHUNK:(2*CHUNK)],len(base))],scope='adversarial',cu=25000)
assert bytes(svm.get_account(job_key.pubkey()).data)==state
corrupt=bytearray(base[CHUNK:(2*CHUNK)]);corrupt[0]^=1
send('conflicting_duplicate_rejected',[upload(BASE_FRAME,CHUNK,corrupt,len(base))],expect_success=False,scope='adversarial',cu=25000)
old_epoch=epoch();reset(BASE_FRAME)
send('stale_generation_rejected',[upload(BASE_FRAME,CHUNK,base[CHUNK:(2*CHUNK)],len(base),old_epoch)],expect_success=False,scope='adversarial',cu=25000)
send('unauthorized_upload_rejected',[ix(bytes([2])+struct.pack('<HHII',BASE_FRAME,len(base),epoch(),0)+base[:CHUNK],
    [meta(job_key.pubkey(),True),meta(second_payer.pubkey(),False,True)])],fee_payer=second_payer,expect_success=False,scope='adversarial',cu=25000)
transfer_frame(BASE_FRAME,base)
assert snapshot()==before
accepted_cache=bytes(svm.get_account(job_key.pubkey()).data)[HEADER:PREVIOUS]

for label,n,a,e,accounts in [
    ('changed_amount',nonce,amount+1,expires,None),('changed_nonce',nonce+1,amount,expires,None),
    ('expired_request',nonce,amount,0,None),
    ('changed_recipient',nonce,amount,expires,[meta(vault,True),meta(second_payer.pubkey(),True),meta(job_key.pubkey(),True)])]:
    send(label,[verify(0,n,a,e,accounts)],expect_success=False,scope='adversarial');assert snapshot()==before

for label,at in [('altered_input_opening',0),('altered_FRI_row',1316),('altered_Merkle_path',2092),('altered_inverse',7148)]:
    assert len(queries[0])==7224
    bad=bytearray(frames[0][1]);bad[15+at]^=1
    transfer_frame(0,bad,scope='adversarial',verify_success=False)
    assert snapshot()==before
    state=bytes(svm.get_account(job_key.pubkey()).data)
    assert state[HEADER:PREVIOUS]==accepted_cache and int.from_bytes(state[113:121],'little')==0
    reset(0)
send('query_skip_rejected',[verify(1)],expect_success=False,scope='adversarial');assert snapshot()==before

bad=bytearray(frames[0][1]);bad[-1]^=1
transfer_frame(0,bad,scope='adversarial',verify_success=False)
state=bytes(svm.get_account(job_key.pubkey()).data)
assert snapshot()==before and int.from_bytes(state[113:121],'little')==0
assert state[HEADER:PREVIOUS]==accepted_cache and state[PREVIOUS:WINDOW]==bytes(7212)
reset(0)

for window_index,(q,data) in enumerate(frames):
    # Recipient-controlled account sizes may change between verification steps.
    account=svm.get_account(recipient)
    svm.set_account(recipient,Account(account.lamports,bytes(64 if window_index%2==0 else 128),account.owner))
    restart_frame=frames[min(3,len(frames)-1)][0]
    row=transfer_frame(q,data,restart=q==restart_frame)
    state=bytes(svm.get_account(job_key.pubkey()).data)
    accepted=min(q+GROUP,64)
    assert int.from_bytes(state[113:121],'little')==accepted and state[HEADER:PREVIOUS]==accepted_cache
    if accepted<64:assert snapshot()==before
    if q==restart_frame:
        send('lost_response_retry_rejected',[verify(q)],expect_success=False,scope='adversarial')
        recovery_events.append({'case':'lost_verification_response','accepted_query_count':accepted,'retry_cannot_advance':True})
        assert snapshot()==before
    if q%16==0 or accepted==64:print(json.dumps({'verified_queries':accepted,'of':64,'CU':row['compute_units']}),flush=True)
records[-1]['operation']='verify_and_withdraw'
after=snapshot()
assert after[0]==before[0]-amount and after[1]==before[1]+amount and int.from_bytes(after[2][40:48],'little')==1
send('replay_rejected',[verify(63)],expect_success=False,scope='adversarial');assert snapshot()==after
send('close_proof_buffer',[ix(bytes([5]),[meta(job_key.pubkey(),True),meta(payer.pubkey(),True,True)])],cu=25000)
assert svm.get_balance(job_key.pubkey()) in (None,0)
positive=[r for r in records if r['scope']=='authorization' and r['success']]
adversarial=[r for r in records if r['scope']=='adversarial']
(OUTPUT/'solana-adversarial.json').write_text(json.dumps({'invalid_opening_rejected':True,'invalid_hint_rejected':True,
    'invalid_Merkle_path_rejected':True,'invalid_inverse_rejected':True,'early_payout_prevented':True,
    'unauthorized_upload_rejected':True,'out_of_order_upload_accepted':True,'duplicate_upload_idempotent':True,
    'conflicting_duplicate_rejected':True,'stale_generation_rejected':True,'query_skip_rejected':True,
    'retry_preserves_verified_prefix':True,'records':adversarial},indent=2)+'\n')
summary={'runtime':f'solders {solders.__version__} LiteSVM','transport':'batched_sorted_queries_with_lossless_delta_window',
    'transaction_version':'v1' if V1 else 'legacy','chunks_per_upload_transaction':PACK,'upload_chunk_bytes':CHUNK,
    'eager_window_completion_probes':EAGER,
    'local_vm_message_format':'Legacy instruction replay with matching inline limits. Signed v1 wires are checked separately.' if V1 else 'legacy',
    'normal_budget_CU':1_400_000,'diagnostic_above_protocol_budget':False,'heap_frame_bytes':262_144,
    'proof_bytes':metadata['proof_bytes'],'capsule_bytes':len(base)+sum(len(data) for _,data in frames),
    'delta_payload_bytes':sum(map(len,queries)),
    'batch_framing_bytes':sum(len(data) for _,data in frames)-sum(map(len,queries)),
    'common_base_bytes':len(base),'expanded_query_bytes':7212,'maximum_encoded_query_bytes':max(map(len,queries)),
    'retained_previous_query_bytes':7212,'cache_bytes':CACHE,'witness_window_bytes':capacity,
    'query_batch_size':GROUP,'proof_fixture_reused':REUSE,
    'withdrawal_lamports':amount,'withdrawal_CU':row['compute_units'],'verification_transactions':1+len(frames),
    'maximum_verification_transaction_CU':max(r['compute_units'] for r in positive if r['operation']!='upload'),
    'proof_buffer_rent_lamports':rent,'proof_buffer_rent_refunded':True,'proof_buffer_space_bytes':space,
    'upload_transactions':sum(r['operation'] in ['upload','upload_with_completion_probe'] for r in positive),
    'completion_probe_transactions':sum(r['operation']=='upload_with_completion_probe' for r in positive),
    'authorization_transactions':len(positive),'network_fee_lamports':sum(r['payer_lamport_delta'] for r in positive),
    'local_positive_transaction_wall_ms':sum(r['local_transaction_wall_ms'] for r in positive),
    'local_vm_submit_ms':sum(r['local_vm_submit_ms'] for r in positive),
    'prover_fixture_wall_ms':prover_fixture_wall_ms,'transport_expansion_ms':transport_expansion_ms,
    'positive_lifecycle_completed':True,'replay_rejected':True,'changed_recipient_rejected':True,
    'invalid_opening_rejected':True,'invalid_hint_rejected':True,'recipient_resize_between_steps_checked':True,
    'independent_relayers_checked':True,'relayer_restart_recovery_checked':True,'recovery_events':recovery_events,
    'latency_scope':'Local CPU time. Network delivery, leader scheduling and finality require live-network measurement.',
    'vault':str(vault),'program':str(pid),'records':[r for r in records if r['scope']!='adversarial']}
(OUTPUT/'solana-vault.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k!='records'},indent=2))

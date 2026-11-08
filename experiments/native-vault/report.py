"""Regenerate the Base/Solana article, fees and local latency record."""
from pathlib import Path
import datetime,hashlib,json,re

ROOT=Path(__file__).resolve().parent
R=ROOT/'results'
def read(name):return json.loads((R/name).read_text())
def write(name,value):(R/name).write_text(json.dumps(value,indent=2)+'\n')
solana_prefix='solana-current-local/'
s=read(solana_prefix+'solana-vault.json');b=read('base/evm-vault.json');q=read('base/fee-quote.json')
sq=read(solana_prefix+'mainnet-layout-quote.json');solana_quote_path=solana_prefix+'mainnet-layout-quote.json'
assert sq['source_receipt_sha256']==hashlib.sha256((R/(solana_prefix+'solana-vault.json')).read_bytes()).hexdigest()
assert sq['broadcast_transactions']==0 and sq['authorization_fee_lamports_by_observed_signer_layouts']==s['network_fee_lamports']
rent_quotes={sq['temporary_account_bytes']:sq['refundable_rent_lamports']}
n=read(solana_prefix+'native-proof.json');nb=read('base/native-proof.json');market=read('market-quotes.json')
assert s['positive_lifecycle_completed'] and b['positive_lifecycle_completed'] and b['chain_id']=='8453'
assert q['chain_id']==8453 and q['broadcast_transactions']==0
assert q['local_fixture_sha256']==hashlib.sha256((R/'base/evm-vault.json').read_bytes()).hexdigest()
assert q['authorization_gas']==b['authorization_gas']
assert q['authorization_transactions']==b['authorization_transactions']
assert b['maximum_authorization_transaction_gas']<=16_777_216
assert b['verifier_code_bytes']<=24_576 and b['vault_code_bytes']<=24_576
assert not s['diagnostic_above_protocol_budget'] and s['maximum_verification_transaction_CU']<=1_400_000
assert s['transaction_version']=='v1' and s['upload_chunk_bytes']==3584
assert max(r['transaction_bytes'] for r in s['records'])<=4096
assert all(r['compute_units']<=r['requested_compute_units']<=1_400_000 for r in s['records'])
assert bytes(nb['request_id']).hex()==b['request_id'][2:]
assert n['authority_commitment']!=nb['authority_commitment'] and n['network_domain']!=nb['network_domain']
assert (R/'preprocessed-cap.bin').read_bytes()==(R/'base/preprocessed-cap.bin').read_bytes()
assert s['proof_buffer_space_bytes']==256+9792+7212+s['witness_window_bytes']
assert 1<=s['query_batch_size']<=5
assert s['verification_transactions']==1+(64+s['query_batch_size']-1)//s['query_batch_size']
assert s['proof_buffer_rent_refunded'] and s['relayer_restart_recovery_checked'] and b['relayer_restart_recovery_checked']
positive=[r for r in s['records'] if r['scope']=='authorization' and r['success']]
assert len(positive)==s['authorization_transactions']
lamports=sum(r['payer_lamport_delta'] for r in positive)
assert lamports==s['network_fee_lamports']>0
sol_fee=lamports/1e9;reserve=rent_quotes[s['proof_buffer_space_bytes']]/1e9
assert s['proof_buffer_rent_lamports']==(s['proof_buffer_space_bytes']+128)*6960
quote_label=datetime.datetime.fromisoformat(q['quoted_at_utc'].replace('Z','+00:00')).strftime('%d %B %Y, %H:%M UTC')
operator_usd=int(q['operator_fee_wei'])/1e18*q['eth_usd']
usd_per_million_gas=int(q['suggested_gas_price_wei'])*1_000_000/1e18*q['eth_usd']
authorization_quotes=[r for r in q['records'] if r['scope']=='authorization']
assert sum(r['gas_used'] for r in authorization_quotes)==b['authorization_gas']
assert sum(int(r['total_fee_wei']) for r in authorization_quotes)==int(q['total_fee_wei'])
block_limit=q['block']['gas_limit']
capacity_blocks=max((b['authorization_gas']+block_limit-1)//block_limit,
    (sum(int(r['estimated_da_footprint_gas']) for r in authorization_quotes)+block_limit-1)//block_limit)
projection={'primary_evm_network':'Base','base':{k:q[k] for k in ['chain_id','authorization_transactions',
    'authorization_gas','execution_fee_usd','l1_data_fee_usd','operator_fee_wei','total_fee_ETH','total_fee_USD',
    'suggested_gas_price_wei','quoted_at_utc','block','scope']},
    'solana_authorization_transactions':len(positive),'solana_authorization_fee_lamports':lamports,
    'solana_authorization_fee_SOL':sol_fee,'solana_authorization_fee_USD':sol_fee*market['sol_usd'],
    'solana_refundable_proof_reserve_SOL':reserve,'solana_refundable_proof_reserve_USD':reserve*market['sol_usd'],
    'solana_mainnet_quote_at_utc':sq['quoted_at_utc'],'solana_local_vm_refunded_reserve_lamports':s['proof_buffer_rent_lamports'],
    'solana_priority_fee_lamports':0,'asset_quote_utc':market['asset_quote_at_utc'],
    'base_execution_USD_per_million_gas':usd_per_million_gas,
    'base_minimum_block_capacity_for_job':capacity_blocks,
    'fee_scope':'One complete successful native withdrawal on each chain. Base includes execution, L1 data and its configured operator charge. Solana reserve is returned in full. Setup, rejected tests and a commercial relayer service price are separate.'}
write('fee-projection.json',projection)

latency={'scope':'Runtime-specific local CPU measurements and separately labeled public Devnet delivery observations.',
    'local_sample_count':1,'local_harness_broadcast_transactions':0,'networks':{}}
for name,receipt,proof in [('Base',b,nb),('Solana',s,n)]:
    latency['networks'][name]={'runtime':receipt['runtime'],'successful_transactions':receipt['authorization_transactions'],
        'wallet_proving_ms':proof['prove_ms'],'native_compiled_verification_ms':proof['compiled_verify_ms'],
        'fixture_prover_process_wall_ms':receipt['prover_fixture_wall_ms'],
        'public_transport_expansion_ms':receipt['transport_expansion_ms'],
        'successful_transaction_wall_ms':receipt['local_positive_transaction_wall_ms'],
        'vm_submit_wall_ms':receipt['local_vm_submit_ms'],
        'local_fixture_processing_ms':receipt['prover_fixture_wall_ms']+receipt['transport_expansion_ms']+receipt['local_positive_transaction_wall_ms'],
        'relayer_recovery_events':receipt['recovery_events']}
if (R/'network-observations.json').exists():latency['read_only_network_observations']='network-observations.json'
write('latency.json',latency)

text=f'''Parano1d-secret native vaults on Base and Solana

Both signed local lifecycles passed. Each vault received one native coin
and released 0.25 after complete proof verification. The final transition
consumed its persistent nonce. Independent relayers completed the jobs.

Base

  Local chain ID:             8453.
  Complete withdrawal:        {b['authorization_transactions']} transactions.
  Total authorization gas:    {b['authorization_gas']:,}.
  Maximum transaction gas:    {b['maximum_authorization_transaction_gas']:,}.
  Per-transaction gas limit:   16,777,216.
  Verifier runtime code:      {b['verifier_code_bytes']:,} bytes.
  Vault runtime code:         {b['vault_code_bytes']:,} bytes.
  Runtime code limit:         24,576 bytes.
  Full network fee estimate:  {q['total_fee_ETH']:.12f} ETH, approximately ${q['total_fee_USD']:.2f}.
  Execution component:        ${q['execution_fee_usd']:.6f}.
  Ethereum data component:    ${q['l1_data_fee_usd']:.6f}.
  Configured operator fee:    ${operator_usd:.6f}.
  Mainnet fee block:          {q['block']['number']:,}.
  Mainnet fee quote:          {q['quoted_at_utc']}.
  Included priority fee:      {int(q['included_priority_fee_wei'])/1e9:.6f} gwei.

The successful local run uses Base chain ID and its own derived authority.
The fee calculation reprices the actual unsigned RLP transactions through
GasPriceOracle.getL1Fee and getOperatorFee at one pinned mainnet block.
The oracle adds signature padding. Local execution gas includes calldata.
The quote checks the L1 fee upper bounds and per-transaction DA footprint.
Shared deployments, wallet creation and rejected tests are separate costs.
The operator component is a Base protocol setting. A commercial relay
service can set its own price separately. No transaction was broadcast.

Solana

  Original native proof:      {s['proof_bytes']:,} bytes.
  Transmitted public witness: {s['capsule_bytes']:,} bytes.
  Complete withdrawal:        {len(positive)} signed transactions.
  Upload-only transactions:   {s['upload_transactions']}.
  Verification windows:       {s['verification_transactions']}, group size {s['query_batch_size']}.
  Maximum verification:       {s['maximum_verification_transaction_CU']:,} CU.
  Protocol CU budget:         1,400,000 per transaction.
  Network transaction fees:   {sol_fee:.6f} SOL, approximately ${sol_fee*market['sol_usd']:.2f}.
  Mainnet reserve quote:      {reserve:.8f} SOL, approximately ${reserve*market['sol_usd']:.2f}.
  Local VM reserve refunded:  {s['proof_buffer_rent_lamports']/1e9:.8f} SOL.
  Reserve fully refunded:     true.
  Temporary account size:     {s['proof_buffer_space_bytes']:,} bytes.
  Persistent vault state:     80 bytes, plus its permanent reserve.

The temporary account holds a 256-byte header, a 9,792-byte verifier cache,
the previous 7,212-byte verified query and a reusable {s['witness_window_bytes']:,}-byte window.
Queries follow the sorted multiset of all 64 transcript indices. Repeated
leaves and authentication nodes are transported by a lossless delta from
the previous verified query. Every expanded query checks four input roots,
five FRI roots, opening reductions, all folds and the final polynomial.
Groups verify every included query before atomically advancing progress.
The last upload and verification share one transaction when they fit.
Fresh proof randomness changes delta sizes and transaction counts.

Every verification step reconstructs the request and checks the vault,
authority, nonce, expiry and parameter identity. A failed or incomplete
query preserves the accepted cache and prefix. The final accepted query
consumes the nonce and releases SOL atomically. Closing the temporary
account returns its full reserve. Network fees use zero priority fee.
Program deployment, account creation outside the job and rejection tests
are priced separately.

Latency and relayer recovery

  Base native proving:        {nb['prove_ms']:.2f} ms.
  Solana native proving:      {n['prove_ms']:.2f} ms.
  Base local VM submissions:  {b['local_vm_submit_ms']/1000:.3f} seconds.
  Solana local VM submissions:{s['local_vm_submit_ms']/1000:.3f} seconds.
  Base local fixture cycle:   {latency['networks']['Base']['local_fixture_processing_ms']/1000:.3f} seconds.
  Solana local fixture cycle: {latency['networks']['Solana']['local_fixture_processing_ms']/1000:.3f} seconds.

These are one-sample CPU measurements on the recorded host. Base uses a
JavaScript EVM, and Solana uses SBF in LiteSVM. Fixture cycles include the
prover's reference checks, public transport expansion and successful
transaction processing. Public Devnet scheduling, inclusion and observed finality are
recorded separately below. Chain transaction counts describe the
transport workload. They do not prescribe one block per transaction.

Base relayer recovery reconstructs the public cache and accepted prefix
after a simulated lost batch response. Solana resumes a partially uploaded
window from its chunk bitmap after client restart and recovers after a
lost verification response. Chunks can arrive concurrently in any order.
Retried old frames cannot advance progress. Altered recipients, amounts,
nonces, expiry, openings, FRI rows, paths and inverses reject. No partial
step releases funds. Recipient-account resizing preserves verification.

Configuration and security

The profile uses KoalaBear Poseidon2 and a hiding FRI proof with 64 queries,
blowup eight, extension degree eight and SHA-256 || Keccak-256 commitments.
The transport optimizations preserve that authority relation and query
multiset. PROTOCOL.txt specifies the acceptance invariant and conditions.
The concrete quantum chosen-request reduction, repeated-use privacy bound
and cryptanalytic assessment concern this exact external-vault profile.
Production security validation includes external review of the verifier
ports, streaming state machine and deployment policy. Mainnet latency and finality under production load remain measurements
for deployment validation.

Evidence

  results/base/evm-vault.json
  results/base/native-proof.json
  results/base/fee-quote.json
  results/{solana_prefix}solana-vault.json
  results/{solana_prefix}solana-adversarial.json
  results/{solana_prefix}stream-native-check.json
  results/fee-projection.json
  results/latency.json
  results/market-quotes.json
  results/host.json

README.txt contains the reproduction commands. Local fixtures use public
research roots. Public Devnet fixtures use an owner-only private research
root and contain public proof and transaction data.
'''
(ROOT/'RESULTS.txt').write_text(text)

table=f'''    <div class="result"><h3>Complete withdrawals on Base and Solana</h3>
      <p>Signed local transactions completed native ETH custody on Base and native SOL custody on Solana. Each vault released 0.25 native coin after full verification. Independent relayers and interrupted-client recovery passed.</p></div>
    <div class="table-wrap"><table><caption>Full successful withdrawal jobs on 8 November 2026. Base is the measured EVM example.</caption>
      <thead><tr><th scope="col">Metric</th><th scope="col">Base (EVM)</th><th scope="col">Solana</th></tr></thead><tbody>
      <tr><td>Complete withdrawal</td><td>{b['authorization_transactions']} transactions</td><td>{len(positive)} transactions and {s['verification_transactions']} ordered verification windows</td></tr>
      <tr><td>Network fee estimate</td><td>${q['total_fee_USD']:.2f}, including L1 data and the configured operator charge</td><td>{sol_fee:.6f} SOL, about ${sol_fee*market['sol_usd']:.2f}, with zero priority fee</td></tr>
      <tr><td>Verification resources</td><td>{b['authorization_gas']:,} gas in total. At most {b['maximum_authorization_transaction_gas']:,} gas per transaction</td><td>At most {s['maximum_verification_transaction_CU']:,} CU per verification transaction</td></tr>
      <tr><td>Temporary witness storage</td><td>Authenticated cache hash in vault storage</td><td>{s['proof_buffer_space_bytes']:,} bytes. Mainnet reserve quote: {reserve:.7f} SOL</td></tr>
      <tr><td>Wallet proof generation</td><td>{nb['prove_ms']:.2f} ms</td><td>{n['prove_ms']:.2f} ms</td></tr>
      <tr><td>Verifier runtime</td><td>{b['verifier_code_bytes']:,} bytes of EVM code</td><td>SBF program executed in LiteSVM</td></tr>
      </tbody></table></div>
    <p>The Base estimate is <strong>${q['execution_fee_usd']:.4f} for execution, ${q['l1_data_fee_usd']:.4f} for Ethereum data and ${operator_usd:.4f} in operator charges</strong>. The <a href="experiments/native-vault/results/base/fee-quote.json">mainnet oracle quote</a> fixes block {q['block']['number']:,} on {quote_label}. It includes a priority fee of {int(q['included_priority_fee_wei'])/1e9:.3f} gwei. Base execution, L1 data and configured operator charges determine the network fee.<sup class="cite"><a href="#ref-17">[17]</a></sup> A relayer service price is a separate commercial choice.</p>
    <p>At this quote, reducing verifier execution by one million gas saves approximately ${usd_per_million_gas:.4f}. The job requires capacity in at least {capacity_blocks} blocks under the recorded execution and DA limits. Actual elapsed time also depends on sequencer ordering, load, submission and confirmation policy.</p>
    <p>The Base run uses chain ID 8453 and a network-specific authority derived from the Parano1d secret. Execution gas comes from <a href="experiments/native-vault/results/base/evm-vault.json">local signed transactions</a>. The <a href="experiments/native-vault/evm/quote-base.mjs">read-only quoting code</a> evaluates every unsigned RLP transaction through <code>getL1Fee</code> and every operator charge through <code>getOperatorFee</code> at one pinned block. The oracle supplies signature padding. The estimate checks each transaction's L1 fee upper bound and DA footprint.</p>
    <p>The Solana account retains a 256-byte header, a 9,792-byte verifier cache, the previous 7,212-byte verified query and a {s['witness_window_bytes']:,}-byte reusable witness window. Its quoted mainnet reserve is {reserve:.7f} SOL. The <a href="experiments/native-vault/results/{solana_quote_path}">read-only mainnet quote</a> records the rent requirement and fees for measured transaction layouts. The account returns its full actual balance on closure. The recorded local job has {s['upload_transactions']} upload or completion-probe transactions, {s['verification_transactions']} completed verification windows, account creation and closure. Fresh proof randomness changes delta sizes and transaction counts. Shared code deployment, vault creation and rejected tests are separate costs.</p>
    <p>Solana v1 supports 4,096-byte signed messages and carries inline compute and account-data limits.<sup class="cite"><a href="#ref-18">[18]</a></sup> The signed local v1 wires are checked directly. LiteSVM executes the same SBF instructions with matching limits expressed through its supported compute-budget path. The public experiments below execute v1 on Devnet.</p>
    <h3>Measured local cycle and relayer recovery</h3>
    <div class="table-wrap"><table><caption>One CPU sample on the recorded Intel Core i7-1365U host. Runtime-specific local measurements.</caption>
      <thead><tr><th scope="col">Stage</th><th scope="col">Base JavaScript EVM harness</th><th scope="col">Solana SBF / LiteSVM harness</th></tr></thead><tbody>
      <tr><td>Native proof generation</td><td>{nb['prove_ms']:.2f} ms</td><td>{n['prove_ms']:.2f} ms</td></tr>
      <tr><td>Public witness expansion</td><td>{b['transport_expansion_ms']:.2f} ms</td><td>{s['transport_expansion_ms']:.2f} ms</td></tr>
      <tr><td>All successful VM submissions</td><td>{b['local_vm_submit_ms']/1000:.3f} s</td><td>{s['local_vm_submit_ms']/1000:.3f} s</td></tr>
      <tr><td>Local fixture processing</td><td>{latency['networks']['Base']['local_fixture_processing_ms']/1000:.3f} s</td><td>{latency['networks']['Solana']['local_fixture_processing_ms']/1000:.3f} s</td></tr>
      </tbody></table></div>
    <p>The <a href="experiments/native-vault/results/latency.json">latency record</a> separates wallet proving, public transport preparation and local VM work. Fixture processing includes the prover's reference checks, witness expansion, signing and successful submissions. It excludes deployment and rejection probes. Separate <a href="experiments/native-vault/results/network-observations.json">read-only RPC observations</a> record endpoint round trips and recent chain cadence. The public Devnet observations below measure delivery, sequencing, inclusion and observed finality for the tested client. Several dependent transactions may execute in one block when ordering and capacity permit.</p>
    <p>The Solana transport accepts {s['upload_chunk_bytes']:,}-byte upload chunks in any arrival order. A protected chunk bitmap supports concurrent delivery and idempotent retries. Each delta uses the previous accepted query, and a group commits only after every query passes. This gives {s['verification_transactions']} ordered verification windows. The recorded {len(positive)} transactions include {s['upload_transactions']} upload or completion-probe transactions, {s['verification_transactions']} completed verification windows, creation and closure. Relayer pipelining must preserve the required execution order and recover missing or rejected uploads. The public runs below record complete cycles with normal and interrupted delivery. Repeated-load median and tail measurements are the next evaluation target.</p>
    <p>Both harnesses reconstruct the accepted progress after an interrupted client. Base recovers its cache from the public proof and authenticates it against the stored hash. Solana resumes a partial window from its persisted chunk bitmap and handles a lost verification response. Old-frame retries preserve the accepted prefix. The <a href="experiments/native-vault/results/{solana_prefix}solana-vault.json">Solana receipts</a>, <a href="experiments/native-vault/results/{solana_prefix}stream-native-check.json">native streaming checks</a> and <a href="experiments/native-vault/RESULTS.txt">full result record</a> provide the recorded cases and resource limits.</p>'''
live=[]
for name,label in [('spare-v1-eager-normal-1','Normal v1 delivery'),('spare-v1-eager-faults-1','Dropped packet and reordered v1 delivery')]:
    directory=R/'solana-devnet'/name
    if not (directory/'independent-audit.json').exists():continue
    receipt=json.loads((directory/'live-result.json').read_text());audit=json.loads((directory/'independent-audit.json').read_text())
    assert audit['live_receipt_sha256']==hashlib.sha256((directory/'live-result.json').read_bytes()).hexdigest()
    assert all(audit[key] for key in ['signed_wires_valid','all_verification_windows_finalized','all_64_query_positions_present',
        'payout_lamport_deltas_verified','complete_reserve_refund_verified','immutable_program_ELF_verified','request_binding_verified','signature_fees_match_balance_deltas'])
    assert receipt['payout_and_nonce_checked'] and receipt['reserve_refunded'] and receipt['program_immutable_verified']
    assert receipt['ordered_verification_windows']==14 and receipt['query_batch_size']==5
    assert receipt['transaction_version']=='v1' and receipt['upload_chunk_bytes']==3584 and receipt['eager_window_completion_probes']
    assert receipt['send_rate_limit_per_s'] is None and not receipt['rpc_send_quota_applies_to_payload']
    live.append({'case':name,'label':label,'network':'Solana Devnet','transaction_version':'v1','upload_chunk_bytes':3584,'confirmed_s':receipt['withdrawal_confirmed_s'],
        'observed_finality_s':receipt['withdrawal_finalized_s'],'proof_preparation_s':receipt['proof_preparation_s'],
        'unique_authorization_transactions':receipt['unique_authorization_transactions'],'rebroadcast_submissions':receipt['rebroadcast_submissions'],
        'network_fee_lamports':receipt['actual_network_fee_lamports'],'refunded_reserve_lamports':receipt['temporary_reserve_lamports'],
        'maximum_verification_CU':max(row['compute_units'] for row in receipt['verification_receipts']),
        'withdrawal_signature':receipt['withdrawal_signature'],'close_signature':receipt['close_signature'],
        'automated_receipt_cross_checks_passed':True,'fault_injection_enabled':receipt['fault_injection_enabled'],
        'receipt':name+'/live-result.json','independent_audit':name+'/independent-audit.json',
        'withdrawal_explorer_url':'https://explorer.solana.com/tx/'+receipt['withdrawal_signature']+'?cluster=devnet'})
if live:
    scope='Public Devnet observations from the research VPS. Timers include proof preparation, temporary-account creation, delivery and observed confirmation. Shared deployment and vault setup precede the timer. Payloads use direct validator TPU QUIC, with RPC and WebSocket state observations.'
    write('solana-devnet/summary.json',{'scope':scope,'cases':live,'real_assets_used':False})
    latency['live_solana_devnet']={'scope':scope,'cases':live}
    write('latency.json',latency)
    with (ROOT/'RESULTS.txt').open('a') as record:
        record.write('\nPublic Solana Devnet withdrawals\n\n'+scope+'\n\n')
        for row in live:
            record.write(f"{row['label']}: confirmed {row['confirmed_s']:.3f} s, finality observed {row['observed_finality_s']:.3f} s, {row['unique_authorization_transactions']} unique transactions, fee {row['network_fee_lamports']/1e9:.6f} test SOL, reserve {row['refunded_reserve_lamports']/1e9:.8f} test SOL returned. Separate finalized-data verification passed.\n")
    table+='''
    <h3>Public Solana Devnet withdrawals</h3>
    <p>Two complete public Devnet jobs released native test SOL after all 64 query checks. The program was deployed with verified ELF bytes and frozen upgrade authority. Each v1 job used fourteen verification windows and direct QUIC delivery to validator TPU ports. Every upload included a conditional completion check. The transaction that completed the bitmap also verified the entire window. Confirmed account notifications advanced the relayer to the next window. RPC supplied state reads and WebSocket notifications.</p>
    <div class="table-wrap"><table><caption>Observed public Devnet withdrawals on 8 November 2026. Each timer starts before fresh proof preparation and includes creation of the temporary proof account. Shared deployment and vault setup precede the timer.</caption>
    <thead><tr><th scope="col">Delivery case</th><th scope="col">Confirmed withdrawal</th><th scope="col">Finality observed</th><th scope="col">Unique transactions</th><th scope="col">Network fee</th></tr></thead><tbody>'''
    for row in live:
        table+=f"<tr><td><a href=\"{row['withdrawal_explorer_url']}\">{row['label']}</a></td><td>{row['confirmed_s']:.2f} s</td><td>{row['observed_finality_s']:.2f} s</td><td>{row['unique_authorization_transactions']}</td><td>{row['network_fee_lamports']/1e9:.6f} test SOL</td></tr>"
    table+='''</tbody></table></div>
    <p>The interrupted-delivery case shuffled the signed window batch and withheld one packet. The relayer recovered missing chunks from the protected bitmap. Repeated transmission reuses the same signed wire until its blockhash expires. This preserves the transaction identity through delivery retries.</p>
    <p>The <a href="experiments/native-vault/results/solana-devnet/summary.json">public Devnet record</a> links the captured runs. A separate read-only verification script checked every captured signature, all fourteen finalized verification transactions, the actual payout balance changes, complete reserve refunds, request binding and immutable program bytes. The observed temporary reserves were '''+f"{min(row['refunded_reserve_lamports'] for row in live)/1e9:.8f} to {max(row['refunded_reserve_lamports'] for row in live)/1e9:.8f} test SOL, returned in full."+'''</p>
    <p>These observations describe the tested client, Devnet scheduling and its confirmation policy. Mainnet latency under production load remains a deployment measurement.</p>'''
networks={'solana_devnet':live,'real_assets_used':False}
base_case=R/'base-sepolia/spare-public-normal-1'
if (base_case/'independent-audit.json').exists():
    br=json.loads((base_case/'live-result.json').read_text())
    ba=json.loads((base_case/'independent-audit.json').read_text())
    assert ba['source_receipt_sha256']==hashlib.sha256((base_case/'live-result.json').read_bytes()).hexdigest()
    assert all(ba[key] for key in ['canonical_receipts_verified','code_hashes_verified','all_64_queries_present',
        'typed_request_verified','payout_balances_verified','nonce_consumed_once','fees_reconciled'])
    assert br['chain_id']==84532 and br['positive_lifecycle_completed'] and br['authorization_transactions']==10
    finality=json.loads((base_case/'finality-observation.json').read_text()) if (base_case/'finality-observation.json').exists() else {}
    networks['base_sepolia']={key:br[key] for key in ['chain_id','confirmed_s','authorization_transactions',
        'authorization_gas','authorization_fee_wei','execution_fee_wei','l1_data_fee_wei','operator_fee_wei',
        'wallet_proving_ms','withdrawal_hash','withdrawal_explorer_url','timing_scope','fee_scope']}
    networks['base_sepolia']['finality_observation']=finality
    latency['live_base_sepolia']=networks['base_sepolia'];write('latency.json',latency)
    fee=int(br['authorization_fee_wei'])/1e18
    safe=finality.get('safe_observed_s');settled=finality.get('finalized_observed_s')
    safe_label=f'{safe:.2f} s' if safe is not None else 'Observation continues'
    settled_label=f'{settled:.2f} s' if settled is not None else 'Observation continues'
    with (ROOT/'RESULTS.txt').open('a') as record:
        record.write(f"\nPublic Base Sepolia withdrawal\n\nL2 receipt confirmation: {br['confirmed_s']:.3f} s. Authorization: {br['authorization_transactions']} transactions, {br['authorization_gas']:,} gas, {fee:.18f} test ETH. Safe observed: {safe_label}. Finalized observed: {settled_label}.\n")
        record.write('A second public RPC verified all signed transactions, canonical receipts, code hashes, typed request, all 64 query positions, nonce consumption, payout balances and fee reconciliation. Mainnet pricing is quoted separately.\n')
    table+=f'''
    <h3>Public Base Sepolia withdrawal</h3>
    <p>A complete public Base Sepolia job released native test ETH after all 64 query checks. The ten authorization transactions consumed {br['authorization_gas']:,} gas and paid {fee:.12f} test ETH in actual receipt fees. The vault consumed its nonce once. Its authority and verifier parameters were checked against the deployed code and public proof.</p>
    <div class="table-wrap"><table><caption>Public Base Sepolia, chain ID 84532, on 8 November 2026. Deployment and deposit precede the timer.</caption>
      <thead><tr><th scope="col">Observation</th><th scope="col">Result</th></tr></thead><tbody>
      <tr><td>L2 receipt confirmation</td><td><a href="{br['withdrawal_explorer_url']}">{br['confirmed_s']:.2f} s</a></td></tr>
      <tr><td>Authorization transactions</td><td>{br['authorization_transactions']}</td></tr>
      <tr><td>Execution gas</td><td>{br['authorization_gas']:,}</td></tr>
      <tr><td>Actual network fee</td><td>{fee:.12f} test ETH</td></tr>
      </tbody></table></div>
    <p>The timer includes fresh proof preparation, witness expansion, read-only rejection checks and ten sequential L2 receipt observations. The separate <a href="experiments/native-vault/results/base-sepolia/spare-public-normal-1/finality-observation.json">finality record</a> records host-network safe and finalized observations. Testnet receipt fees and the pinned Base Mainnet dollar estimate have separate scopes.</p>
    <p>A <a href="experiments/native-vault/results/base-sepolia/spare-public-normal-1/independent-audit.json">read-only cross-check through a second public RPC</a> verified every signed transaction, canonical block membership, deployed code hashes, request fields, all query positions, payout balances, nonce consumption and exact fee reconciliation. The <a href="experiments/native-vault/results/base-sepolia/spare-public-normal-1/live-result.json">public result</a> contains the complete transaction journal.</p>'''
write('public-network-summary.json',networks)
figure=ROOT.parent.parent/'assets/04-public-v1-latency.svg'
if 'base_sepolia' in networks and figure.exists():
    svg=figure.read_text();svg=svg[svg.index('<svg'):]
    table+='''
    <figure id="figure-4"><div class="diagram-frame">'''+svg+'''</div>
      <div class="figure-actions"><a href="assets/04-public-v1-latency.svg">SVG</a><a href="assets/04-public-v1-latency.png">PNG</a></div>
      <figcaption><strong>Figure 4.</strong> Public authorization runs with receipt cross-checks. Each timer begins before proof preparation. Solana includes temporary-account creation and confirmed account observations. Base includes read-only rejection checks and L2 receipt observations. Shared deployment and deposits precede both timers. Finality levels appear separately in the result records.</figcaption>
    </figure>'''
article=ROOT.parent.parent/'index.html'
if article.exists():
    html=article.read_text()
    html,count=re.subn(r'(<!-- local-results:start -->).*?(<!-- local-results:end -->)',lambda m:m[1]+'\n'+table+'\n    '+m[2],html,flags=re.S)
    assert count==1
    article.write_text(html)
print(json.dumps(projection,indent=2))

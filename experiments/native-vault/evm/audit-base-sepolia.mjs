// Read-only cross-check against a second public Base Sepolia RPC.
import {readFile,writeFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import path from 'node:path';
const [tools,caseDirectory]=process.argv.slice(2);
const option=(name,fallback)=>{const i=process.argv.indexOf(name);return i<0?fallback:process.argv[i+1];};
const {Interface,Transaction,keccak256,solidityPacked}=await import(pathToFileURL(path.resolve(tools,'node_modules/ethers/lib.esm/index.js')).href);
const file=path.resolve(caseDirectory,'live-result.json'),bytes=await readFile(file),r=JSON.parse(bytes);
const endpoint='https://base-sepolia-rpc.publicnode.com';
let id=0;
async function rpc(method,params=[]){
 const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','User-Agent':'Parano1dX-public-audit/0.1'},
  body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params}),signal:AbortSignal.timeout(25000)});
 if(!response.ok)throw Error('HTTP '+response.status);
 const body=await response.json();if(body.error)throw Error(body.error.message);return body.result;
}
const assert=(condition,description)=>{if(!condition)throw Error(description);};
assert(BigInt(await rpc('eth_chainId'))===84532n&&r.chain_id===84532&&!r.real_assets_used,'Base Sepolia');
const compiled=JSON.parse(await readFile(path.resolve(option('--compiled',path.join(tools,'compiled.json'))),'utf8'));
const vaultInterface=new Interface(compiled['Parano1dVault.sol'].Parano1dVault.abi);
async function view(name,args=[],block='latest'){
 return vaultInterface.decodeFunctionResult(name,await rpc('eth_call',[{to:r.vault,data:vaultInterface.encodeFunctionData(name,args)},block]))[0];
}
let allFees=0n,authFees=0n,authGas=0n;const seen=new Set(),receipts=[];
for(const row of r.records){
 const tx=Transaction.from(row.transaction_hex);
 assert(tx.isSigned()&&tx.chainId===84532n&&tx.from.toLowerCase()===row.from.toLowerCase()&&tx.nonce===row.nonce,'Signed transaction');
 assert(tx.hash===row.hash&&!seen.has(tx.hash),'Unique hash');seen.add(tx.hash);
 const receipt=await rpc('eth_getTransactionReceipt',[row.hash]);
 assert(receipt&&receipt.status==='0x1'&&receipt.blockHash===row.receipt.blockHash,'Successful canonical receipt');
 const block=await rpc('eth_getBlockByNumber',[receipt.blockNumber,false]);
 assert(block.hash===receipt.blockHash&&block.transactions.includes(row.hash),'Canonical block membership');
 const gas=BigInt(receipt.gasUsed),execution=gas*BigInt(receipt.effectiveGasPrice),l1=BigInt(receipt.l1Fee??0);
 const operator=BigInt(receipt.operatorFeeScalar??0)*gas/1_000_000n+BigInt(receipt.operatorFeeConstant??0),fee=execution+l1+operator;
 assert(gas===BigInt(row.gas_used)&&fee===BigInt(row.total_fee_wei),'Receipt fee accounting');
 allFees+=fee;
 if(row.scope==='authorization'){authFees+=fee;authGas+=gas;
  const decoded=vaultInterface.decodeFunctionData('authorize',tx.data);
  assert(tx.to.toLowerCase()===r.vault.toLowerCase()&&decoded.recipient.toLowerCase()===r.recipient.toLowerCase()&&decoded.amount===BigInt(r.withdrawal_wei)&&decoded.expiry===BigInt(r.expiry_block),'Request fields');
 }
 receipts.push({hash:row.hash,block_number:Number(BigInt(receipt.blockNumber)),block_hash:receipt.blockHash,gas_used:gas.toString(),total_fee_wei:fee.toString()});
}
assert(allFees===BigInt(r.total_experiment_fee_wei)&&authFees===BigInt(r.authorization_fee_wei)&&authGas===BigInt(r.authorization_gas),'Experiment totals');
const auth=r.records.filter(x=>x.scope==='authorization');assert(auth.length===r.authorization_transactions,'Complete authorization steps');
const counts=auth.map(x=>vaultInterface.decodeFunctionData('authorize',Transaction.from(x.transaction_hex).data).queries.length);
assert(counts[0]===0&&counts.every(n=>n>=0&&n<=12)&&counts.reduce((sum,n)=>sum+n,0)===64,'All 64 query positions');
for(const item of [r.verifier,r.factory]){
 const code=await rpc('eth_getCode',[item.address,'latest']);assert(keccak256(code)===item.code_keccak256,'Runtime code hash');
}
assert((await view('authority')).toLowerCase()===r.authority_commitment.toLowerCase(),'Authority commitment');
assert((await view('parameters')).toLowerCase()===r.parameters.toLowerCase(),'Parameter identity');
assert((await view('verifier')).toLowerCase()===r.verifier.address.toLowerCase(),'Verifier binding');
const beforeNonce=BigInt(r.before.nonce),packed=solidityPacked(['string','uint256','address','bytes32','uint256','address','uint256','uint256'],
 ['Parano1dX/v1/withdraw/EVM',84532n,r.vault,r.parameters,beforeNonce,r.recipient,BigInt(r.withdrawal_wei),BigInt(r.expiry_block)]);
const request='0x'+createHash('sha256').update(Buffer.from(packed.slice(2),'hex')).digest('hex');assert(request===r.request_id,'Typed request hash');
const requestContext=keccak256(packed);
const nativeProof=JSON.parse(await readFile(path.resolve(caseDirectory,'native-proof.json'),'utf8'));
assert(Buffer.from(nativeProof.request_context).toString('hex')===requestContext.slice(2),'Native request context');
const finalBlock=auth.at(-1).receipt.blockNumber;
assert(await view('nonce',[],finalBlock)===beforeNonce+1n,'Nonce consumed once');
const vaultBalance=BigInt(await rpc('eth_getBalance',[r.vault,finalBlock])),recipientBalance=BigInt(await rpc('eth_getBalance',[r.recipient,finalBlock]));
assert(vaultBalance===BigInt(r.before.vault)-BigInt(r.withdrawal_wei)&&recipientBalance===BigInt(r.before.recipient)+BigInt(r.withdrawal_wei),'Payout balances at withdrawal block');
const payerBalance=BigInt(await rpc('eth_getBalance',[r.payer,finalBlock]));
assert(BigInt(r.payer_balance_before)-payerBalance===allFees+BigInt(r.deposit_wei),'Payer fee reconciliation');
const result={audited_at_utc:new Date().toISOString(),rpc_endpoint:endpoint,chain_id:84532,
 source_receipt_sha256:createHash('sha256').update(bytes).digest('hex'),signed_transactions_checked:seen.size,
 canonical_receipts_verified:true,code_hashes_verified:true,all_64_queries_present:true,typed_request_verified:true,
 native_request_context_verified:true,request_context:requestContext,
 payout_balances_verified:true,nonce_consumed_once:true,fees_reconciled:true,withdrawal_hash:r.withdrawal_hash,receipts,
 scope:'Read-only automated cross-check through an RPC independent of the submitting endpoint.'};
await writeFile(path.resolve(caseDirectory,'independent-audit.json'),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({...result,receipts:undefined},null,2));

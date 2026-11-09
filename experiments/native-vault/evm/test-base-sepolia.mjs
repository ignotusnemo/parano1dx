// Public testnet experiment. Every write is guarded by Base Sepolia chain ID.
// Fee keys and the Parano1d secret are read only from an owner-only directory.
import {readFile,writeFile,mkdir,stat,appendFile} from 'node:fs/promises';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import path from 'node:path';

const [toolDir,prover,pythonTools,keyDir]=process.argv.slice(2);
const option=(name,fallback)=>{const i=process.argv.indexOf(name);return i<0?fallback:process.argv[i+1];};
const run=option('--run','public-normal-1');
if(!/^[a-z0-9_-]+$/.test(run))throw Error('Invalid run name');
const {Interface,AbiCoder,Wallet,keccak256,getCreateAddress}=await import(pathToFileURL(path.resolve(toolDir,'node_modules/ethers/lib.esm/index.js')).href);
const here=path.dirname(fileURLToPath(import.meta.url));
const results=path.resolve(here,'../results/base-sepolia',run);
await mkdir(path.dirname(results),{recursive:true});
await mkdir(results);
const endpoint=option('--rpc','https://sepolia.base.org');
const records=[],observations=[];
let rpcId=0;
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const json=x=>JSON.stringify(x,(_,v)=>typeof v==='bigint'?v.toString():v,2)+'\n';
async function rpc(method,params=[]){
 for(let attempt=0;attempt<5;attempt++){
  try{
   const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','User-Agent':'Parano1dX-public-research/0.1'},
    body:JSON.stringify({jsonrpc:'2.0',id:++rpcId,method,params}),signal:AbortSignal.timeout(25000)});
   if(!response.ok)throw Error('HTTP '+response.status);
   const body=await response.json();
   if(body.error){const e=Error(body.error.message);e.rpc=body.error;throw e;}
   if(body.result===undefined)throw Error('Missing RPC result');
   return body.result;
  }catch(error){
   if(error.rpc||attempt===4)throw error;
   observations.push({event:'rpc_retry',method,attempt:attempt+1});await pause(500*(attempt+1));
  }
 }
}
const networkId=async()=>BigInt(await rpc('eth_chainId'));
if(await networkId()!==84532n)throw Error('Base Sepolia required');
async function privateJSON(name){
 const file=path.join(keyDir,name);if((await stat(file)).mode&0o077)throw Error('Fee key must be owner-only');
 return JSON.parse(await readFile(file,'utf8'));
}
const saved=await privateJSON('relayer.json');
if(saved.chainId!==84532)throw Error('Testnet-only fee key required');
let payer=new Wallet(saved.privateKey);
if(payer.address!==saved.address)throw Error('Fee address mismatch');
const recipientFile=path.join(keyDir,run+'-recipient.json');
let recipient;
try{recipient=new Wallet((await privateJSON(run+'-recipient.json')).privateKey);}
catch(e){if(e.code!=='ENOENT')throw e;recipient=Wallet.createRandom();await writeFile(recipientFile,json({address:recipient.address,privateKey:recipient.privateKey,chainId:84532}),{mode:0o600,flag:'wx'});}
let nextNonce=Number(BigInt(await rpc('eth_getTransactionCount',[payer.address,'pending'])));
const balance=async address=>BigInt(await rpc('eth_getBalance',[address,'latest']));
const initialPayerBalance=await balance(payer.address);
if(initialPayerBalance<1_000_000_000_000_000n)throw Error('At least 0.001 free Base Sepolia ETH is needed for setup, deposit and measured authorization');
const compiledFile=path.resolve(option('--compiled',path.join(toolDir,'compiled.json')));
const compiled=JSON.parse(await readFile(compiledFile,'utf8'));
const receiptOf=hash=>rpc('eth_getTransactionReceipt',[hash]);
async function waitReceipt(hash){
 const began=performance.now();
 while(performance.now()-began<180000){const r=await receiptOf(hash);if(r)return r;await pause(250);}
 throw Error('Receipt deadline for '+hash);
}
async function persist(){await writeFile(path.join(results,'transaction-journal.json'),json(records));}
async function send(operation,to,data,value=0n,scope='setup'){
 if(await networkId()!==84532n)throw Error('Write refused outside Base Sepolia');
 const gasPrice=BigInt(await rpc('eth_gasPrice'));
 if(gasPrice>10_000_000_000n)throw Error('Unexpected testnet gas quote');
 const tx={type:0,chainId:84532n,nonce:nextNonce,to,data,value,gasLimit:16_777_216n,gasPrice};
 const raw=await payer.signTransaction(tx),hash=keccak256(raw);
 const row={operation,scope,hash,from:payer.address,to:to??null,value_wei:value.toString(),nonce:nextNonce,
  gas_limit:16777216,gas_price_wei:gasPrice.toString(),transaction_bytes:(raw.length-2)/2,
  transaction_hex:raw,submitted_at_utc:new Date().toISOString()};
 records.push(row);await persist();const began=performance.now();
 const submitted=await rpc('eth_sendRawTransaction',[raw]);if(submitted.toLowerCase()!==hash.toLowerCase())throw Error('Transaction hash mismatch');
 nextNonce++;const receipt=await waitReceipt(hash);row.receipt=receipt;row.confirmed_after_s=(performance.now()-began)/1000;
 row.confirmed_at_utc=new Date().toISOString();row.gas_used=Number(BigInt(receipt.gasUsed));
 row.execution_fee_wei=(BigInt(receipt.gasUsed)*BigInt(receipt.effectiveGasPrice)).toString();
 row.l1_fee_wei=BigInt(receipt.l1Fee??0).toString();row.operator_fee_wei=(BigInt(receipt.operatorFeeScalar??0)*BigInt(receipt.gasUsed)/1_000_000n+BigInt(receipt.operatorFeeConstant??0)).toString();
 row.total_fee_wei=(BigInt(row.execution_fee_wei)+BigInt(row.l1_fee_wei)+BigInt(row.operator_fee_wei)).toString();
 await persist();console.log(json({...row,receipt:undefined,transaction_hex:undefined}).trim());
 if(BigInt(receipt.status)!==1n)throw Error('Transaction reverted: '+hash);
 return row;
}
async function view(address,iface,name,args=[]){
 return iface.decodeFunctionResult(name,await rpc('eth_call',[{to:address,data:iface.encodeFunctionData(name,args)},'latest']));
}
async function deploy(file,name,args=[]){
 const c=compiled[file][name],iface=new Interface(c.abi),codeBytes=c.evm.deployedBytecode.object.length/2;
 if(codeBytes>24576)throw Error('Runtime code-size limit');
 const expected=getCreateAddress({from:payer.address,nonce:nextNonce});
 const row=await send('deploy_'+name,undefined,'0x'+c.evm.bytecode.object+iface.encodeDeploy(args).slice(2));
 if(row.receipt.contractAddress.toLowerCase()!==expected.toLowerCase())throw Error('Deployment address mismatch');
 const code=await rpc('eth_getCode',[expected,'latest']);if((code.length-2)/2!==codeBytes)throw Error('Deployed code length mismatch');
 return {address:expected,iface,codeBytes,codeHash:keccak256(code),deployment:row.hash};
}
const network=createHash('sha256').update('Parano1dX/network/EVM').update(Buffer.from((84532n).toString(16).padStart(64,'0'),'hex')).digest('hex');
const rootFile=path.resolve(keyDir,'authority-root.bin');
if((await stat(rootFile)).mode&0o077)throw Error('Authority root must be owner-only');
const proofEnv={...process.env,PARANO1DX_RESEARCH_ROOT_FILE:rootFile};
execFileSync(prover,[results,'0'.repeat(64),network],{stdio:'inherit',env:proofEnv});
let metadata=JSON.parse(await readFile(path.join(results,'native-proof.json'),'utf8'));
if(metadata.root_source!=='private research file')throw Error('Private root required for live custody');
const bytes32=xs=>'0x'+Buffer.from(xs).toString('hex');
const checker=await deploy('VVerifier.sol','VVerifier');
const factory=await deploy('Parano1dFactory.sol','Parano1dFactory',[checker.address,bytes32(metadata.parameter_id)]);
const [vaultAddress]=await view(factory.address,factory.iface,'addressOf',[bytes32(metadata.authority_commitment),0]);
await send('create_vault',factory.address,factory.iface.encodeFunctionData('create',[bytes32(metadata.authority_commitment),0]));
const vaultCode=compiled['Parano1dVault.sol'].Parano1dVault;
const vault={address:vaultAddress,iface:new Interface(vaultCode.abi)};
if((await rpc('eth_getCode',[vault.address,'latest'])).length!==2+vaultCode.evm.deployedBytecode.object.length)throw Error('CREATE2 code mismatch');
const deposit=10_000_000_000_000n,amount=2_500_000_000_000n;
await send('deposit_native_test_ETH',vault.address,'0x',deposit);
const expiry=BigInt(await rpc('eth_blockNumber'))+10000n;
const [request]=await view(vault.address,vault.iface,'requestId',[recipient.address,amount,expiry]);
const [context]=await view(vault.address,vault.iface,'requestContext',[recipient.address,amount,expiry]);
const identity={network:'Base Sepolia',chain_id:84532,run,payer:payer.address,recipient:recipient.address,
 verifier:{address:checker.address,code_bytes:checker.codeBytes,code_keccak256:checker.codeHash,deployment_hash:checker.deployment},
 factory:{address:factory.address,code_keccak256:factory.codeHash,deployment_hash:factory.deployment},
 vault:vault.address,authority_commitment:bytes32(metadata.authority_commitment),parameters:bytes32(metadata.parameter_id),
 network_domain:network,request_id:request,expiry_block:expiry.toString(),withdrawal_wei:amount.toString(),deposit_wei:deposit.toString(),
 rpc_url:endpoint,started_at_utc:new Date().toISOString()};
await writeFile(path.join(results,'public-manifest.json'),json(identity));
const began=performance.now(),proofBegan=performance.now();
execFileSync(prover,[results,request.slice(2),network,context.slice(2)],{stdio:'inherit',env:proofEnv});
const proofPreparationMs=performance.now()-proofBegan,expansionBegan=performance.now();
execFileSync('python3',[path.join(here,'prepare.py'),results],{stdio:'inherit',env:{...process.env,PYTHONPATH:pythonTools}});
const expansionMs=performance.now()-expansionBegan;
metadata=JSON.parse(await readFile(path.join(results,'native-proof.json'),'utf8'));
const fixture=JSON.parse(await readFile(path.join(results,'evm-fixture.json'),'utf8')),b=fixture.base;
const base=[b.evaluations,b.roots,b.finalPolynomial,b.outputs,b.outerInverses,b.queryPowWitness];
const query=q=>[q.leaves,q.paths,q.inverses];
const [challenges]=await view(checker.address,checker.iface,'transcript',[base,request,context]);
for(const name of ['alpha','zeta','pcsAlpha'])if(challenges[name]!==BigInt(fixture.reference[name]))throw Error('Native transcript mismatch');
if(challenges.indices.some((v,i)=>v!==BigInt(fixture.reference.indices[i])))throw Error('Native index mismatch');
let cacheBytes='0x';
const encode=(a,queries,who=recipient.address,cache=cacheBytes)=>vault.iface.encodeFunctionData('authorize',[who,a,expiry,base,queries,cache]);
const snapshot=async()=>({vault:await balance(vault.address),recipient:await balance(recipient.address),nonce:(await view(vault.address,vault.iface,'nonce'))[0]});
const before=await snapshot();
async function unchanged(){if(json(await snapshot())!==json(before))throw Error('Premature payout');}
async function reject(operation,data){
 let rejected=false;
 try{await rpc('eth_call',[{from:payer.address,to:vault.address,data,gas:'0x1000000'},'latest']);}
 catch(e){if(!e.rpc||(!/revert/i.test(e.message)&&e.rpc.code!==3))throw e;rejected=true;}
 if(!rejected)throw Error('Expected rejection: '+operation);
 observations.push({event:operation,rejected_by:'eth_call'});await unchanged();
}
await reject('changed_amount_rejected',encode(amount+1n,[]));
await send('begin_authorization',vault.address,encode(amount,[]),0n,'authorization');await unchanged();
const [cache]=await view(checker.address,checker.iface,'prepareCache',[base,request,context]);
const cacheType=checker.iface.getFunction('prepareCache').outputs[0];cacheBytes=AbiCoder.defaultAbiCoder().encode([cacheType],[cache]);
const baseType=vault.iface.getFunction('authorize').inputs[3];
const jobMessage=AbiCoder.defaultAbiCoder().encode(['bytes32','bytes32',baseType],[request,context,base]);
const job='0x'+createHash('sha256').update(Buffer.from(jobMessage.slice(2),'hex')).digest('hex');const jobOther=keccak256(jobMessage);
const bad=structuredClone(fixture.queries[0]),altered=Buffer.from(bad.leaves[0].slice(2),'hex');altered[0]^=1;bad.leaves[0]='0x'+altered.toString('hex');
await reject('altered_proof_rejected',encode(amount,[query(bad)]));
const wrong=fixture.queries.find((_,i)=>fixture.reference.indices[i]!==fixture.reference.indices[0]);
await reject('query_skip_rejected',encode(amount,[query(wrong)]));
const corruptCache='0x'+(BigInt('0x'+cacheBytes.slice(2,66))^1n).toString(16).padStart(64,'0')+cacheBytes.slice(66);
await reject('altered_cache_rejected',encode(amount,[query(fixture.queries[0])],recipient.address,corruptCache));
for(let start=0;start<64;start+=12){
 if(start===24){
  // Recreate the fee signer and recover accepted progress and cache from public state.
  payer=new Wallet((await privateJSON('relayer.json')).privateKey);
  nextNonce=Number(BigInt(await rpc('eth_getTransactionCount',[payer.address,'pending'])));
  const [progress]=await view(vault.address,vault.iface,'progress',[job,jobOther]);if(progress!==25n)throw Error('Recovery progress');
  const [rebuilt]=await view(checker.address,checker.iface,'prepareCache',[base,request,context]);
  cacheBytes=AbiCoder.defaultAbiCoder().encode([cacheType],[rebuilt]);
  const [stored]=await view(vault.address,vault.iface,'cacheHashes',[job,jobOther]);if(stored!==keccak256(cacheBytes))throw Error('Recovery cache binding');
  observations.push({event:'relayer_reconstructed_after_24_queries',progress:Number(progress),cache_hash:stored});
 }
 await send(start+12>=64?'verify_and_withdraw':'verify_query_batch',vault.address,encode(amount,fixture.queries.slice(start,start+12).map(query)),0n,'authorization');
 if(start+12<64)await unchanged();
}
const confirmedS=(performance.now()-began)/1000,after=await snapshot();
if(after.vault!==before.vault-amount||after.recipient!==before.recipient+amount||after.nonce!==before.nonce+1n)throw Error('Withdrawal state mismatch');
const final=records.filter(r=>r.scope==='authorization').at(-1);
let replayRejected=false;try{await rpc('eth_call',[{from:payer.address,to:vault.address,data:encode(amount,[]),gas:'0x1000000'},'latest']);}
catch(e){if(!e.rpc)throw e;replayRejected=true;}if(!replayRejected)throw Error('Replay accepted');
const sum=(rows,key)=>rows.reduce((s,r)=>s+BigInt(r[key]),0n),authorization=records.filter(r=>r.scope==='authorization');
const finalPayerBalance=await balance(payer.address),allFees=sum(records,'total_fee_wei');
if(initialPayerBalance-finalPayerBalance!==deposit+allFees)throw Error('Payer delta differs from deposit plus receipt fees');
let safeAt=null,finalizedAt=null;const finalBlock=BigInt(final.receipt.blockNumber);
const result={...identity,positive_lifecycle_completed:true,authorization_transactions:authorization.length,
 confirmed_s:confirmedS,proof_preparation_ms:proofPreparationMs,transport_expansion_ms:expansionMs,wallet_proving_ms:metadata.prove_ms,
 authorization_gas:authorization.reduce((s,r)=>s+r.gas_used,0),maximum_authorization_transaction_gas:Math.max(...authorization.map(r=>r.gas_used)),
 authorization_fee_wei:sum(authorization,'total_fee_wei'),execution_fee_wei:sum(authorization,'execution_fee_wei'),
 l1_data_fee_wei:sum(authorization,'l1_fee_wei'),operator_fee_wei:sum(authorization,'operator_fee_wei'),
 total_experiment_fee_wei:allFees,payer_balance_reconciled:true,payer_balance_before:initialPayerBalance,payer_balance_after:finalPayerBalance,
 before,after,withdrawal_hash:final.hash,withdrawal_explorer_url:'https://sepolia.basescan.org/tx/'+final.hash,
 native_transcript_matches:true,replay_rejected:true,observations,records,
 timing_scope:`Proof preparation, expansion, read-only adversarial checks and ${authorization.length} sequential L2 receipt observations. Shared deployment and deposit precede the timer.`,
 fee_scope:'Actual Base Sepolia receipt fees in test ETH. Mainnet pricing is a separate read-only quote.',real_assets_used:false};
result.finality_observation_file='finality-observation.json';
await writeFile(path.join(results,'live-result.json'),json(result));
console.log(json({...result,records:undefined,observations:undefined}).trim());
// L1 publication/finality is reported separately from L2 inclusion.
const finalityBegan=performance.now();
while(performance.now()-finalityBegan<1200000){
 for(const tag of ['safe','finalized']){
  const block=await rpc('eth_getBlockByNumber',[tag,false]);
  if(BigInt(block.number)>=finalBlock){if(tag==='safe'&&safeAt===null)safeAt=(performance.now()-began)/1000;if(tag==='finalized'&&finalizedAt===null)finalizedAt=(performance.now()-began)/1000;}
 }
 await writeFile(path.join(results,'finality-observation.json'),json({chain_id:84532,withdrawal_hash:final.hash,
  confirmed_s:confirmedS,safe_observed_s:safeAt,finalized_observed_s:finalizedAt,observed_at_utc:new Date().toISOString(),
  scope:'Separate L1 publication and finality observations. Null means the level has not yet been observed.'}));
 if(finalizedAt!==null)break;
 await pause(10000);
}
console.log(json({complete:true,confirmed_s:confirmedS,safe_observed_s:safeAt,finalized_observed_s:finalizedAt}).trim());

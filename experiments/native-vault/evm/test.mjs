// Complete local native-asset lifecycle. No RPC or real accounts are used.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import path from 'node:path';
const [toolDir,prover,pythonTools]=process.argv.slice(2);
const load=relative=>import(pathToFileURL(path.join(toolDir,'node_modules',relative)).href);
const {default:solc}=await load('solc/index.js');
const {Interface,AbiCoder,keccak256}=await load('ethers/lib.esm/index.js');
const here=path.dirname(fileURLToPath(import.meta.url));
const option=(name,fallback)=>{const i=process.argv.indexOf(name);return i<0?fallback:process.argv[i+1];};
const chainId=BigInt(option('--chain-id','8453'));
const blockNumber=BigInt(option('--block-number','1'));
const groupSize=Number(option('--group-size','12'));
if(!Number.isInteger(groupSize)||groupSize<1||groupSize>12)throw Error('Invalid query group size');
const resultName=option('--result-name',chainId===8453n?'optimized-evm':'evm');
if(!/^[a-z0-9_-]+$/.test(resultName))throw Error('Invalid result directory');
const results=path.resolve(here,'../results',resultName);
await mkdir(results,{recursive:true});
const sources={};
for(const name of ['VField.sol','VParameters.sol','VSampler.sol','VVerifier.sol','Parano1dVault.sol','Parano1dFactory.sol'])sources[name]={content:await readFile(path.join(here,name),'utf8')};
const compiled=JSON.parse(solc.compile(JSON.stringify({language:'Solidity',sources,settings:{
  optimizer:{enabled:true,runs:200},viaIR:true,evmVersion:'cancun',
  outputSelection:{'*':{'*':['abi','evm.bytecode.object','evm.deployedBytecode.object']}}
}})));
const errors=compiled.errors?.filter(x=>x.severity==='error')||[];
if(errors.length)throw Error(errors.map(e=>e.formattedMessage).join('\n'));
await writeFile(path.join(results,'compiled.json'),JSON.stringify(compiled.contracts));
if(process.argv.includes('--compile-only')){
  for(const [file,contracts]of Object.entries(compiled.contracts))for(const [name,c]of Object.entries(contracts))console.log(name,c.evm.deployedBytecode.object.length/2,c.evm.bytecode.object.length/2);
  process.exit(0);
}
const {createVM,runTx}=await load('@ethereumjs/vm/dist/esm/index.js');
const {createLegacyTx}=await load('@ethereumjs/tx/dist/esm/index.js');
const {createBlock}=await load('@ethereumjs/block/dist/esm/index.js');
const {Common,Mainnet,Hardfork}=await load('@ethereumjs/common/dist/esm/index.js');
const {Account,createAddressFromPrivateKey,createAddressFromString,hexToBytes,bytesToHex}=await load('@ethereumjs/util/dist/esm/index.js');
const common=new Common({chain:{...Mainnet,chainId:Number(chainId)},hardfork:Hardfork.Prague});
const vm=await createVM({common});
const key=new Uint8Array(32).fill(31);const payer=createAddressFromPrivateKey(key);
const secondKey=new Uint8Array(32).fill(32);const secondPayer=createAddressFromPrivateKey(secondKey);
const recipient=createAddressFromString('0x1234567890123456789012345678901234567890');
await vm.stateManager.putAccount(payer,new Account(0n,1000n*10n**18n));
await vm.stateManager.putAccount(secondPayer,new Account(0n,1000n*10n**18n));
const block=createBlock({header:{number:blockNumber,gasLimit:60_000_000n,baseFeePerGas:0n}},{common});
const records=[];
async function send(operation,to,data,value=0n,success=true,alternate=false){
  const started=performance.now();
  const sender=alternate?secondPayer:payer;const signingKey=alternate?secondKey:key;
  const account=await vm.stateManager.getAccount(sender);
  const tx=createLegacyTx({nonce:account.nonce,to,data:hexToBytes(data),value,gasLimit:16_777_216n,gasPrice:1n},{common}).sign(signingKey);
  if(tx.serialize().length>131072)throw Error('Transaction exceeds the 128 KiB transport ceiling');
  const submitted=performance.now();
  const out=await runTx(vm,{tx,block});
  const ended=performance.now();
  const failed=!!out.execResult.exceptionError;
  const record={operation,success:!failed,gas:Number(out.totalGasSpent),
    transaction_bytes:tx.serialize().length,calldata_bytes:hexToBytes(data).length,
    local_transaction_wall_ms:ended-started,local_vm_submit_ms:ended-submitted,
    fee_payer:sender.toString(),error:out.execResult.exceptionError?.error||null,return_data:bytesToHex(out.execResult.returnValue)};
  records.push(record);
  record.transaction_hex='0x'+Buffer.from(tx.serialize()).toString('hex');
  console.log(JSON.stringify({...record,transaction_hex:undefined,return_data:record.return_data.slice(0,140)}));
  if(failed===success){await writeFile(path.join(results,'evm-attempt.json'),JSON.stringify(records,null,2));throw Error(JSON.stringify(record));}
  return out;
}
async function view(to,iface,name,args){
  await vm.stateManager.checkpoint();
  const out=await vm.evm.runCall({to,caller:payer,origin:payer,data:hexToBytes(iface.encodeFunctionData(name,args)),gasLimit:16_777_216n,block});
  await vm.stateManager.revert();
  if(out.execResult.exceptionError)throw Error(name+': '+out.execResult.exceptionError.error+' '+bytesToHex(out.execResult.returnValue));
  return iface.decodeFunctionResult(name,bytesToHex(out.execResult.returnValue));
}
async function deploy(file,name,args=[],value=0n){
  const c=compiled.contracts[file][name];
  const iface=new Interface(c.abi);const bytes=c.evm.deployedBytecode.object.length/2;
  if(bytes>24576)throw Error(name+': runtime exceeds EIP-170: '+bytes);
  const init='0x'+c.evm.bytecode.object+iface.encodeDeploy(args).slice(2);
  const out=await send('deploy_'+name,undefined,init,value);
  return {address:out.createdAddress,iface,bytes};
}
const network=createHash('sha256').update('Parano1dX/network/EVM').update(Buffer.from(chainId.toString(16).padStart(64,'0'),'hex')).digest('hex');
execFileSync(prover,[results,'0'.repeat(64),network],{stdio:'inherit'});
let metadata=JSON.parse(await readFile(path.join(results,'native-proof.json'),'utf8'));
const bytes32=xs=>'0x'+Buffer.from(xs).toString('hex');
const checker=await deploy('VVerifier.sol','VVerifier');
const factory=await deploy('Parano1dFactory.sol','Parano1dFactory',[checker.address.toString(),bytes32(metadata.parameter_id)]);
const [expectedAddress]=await view(factory.address,factory.iface,'addressOf',[bytes32(metadata.authority_commitment),0]);
await send('create_vault',factory.address,factory.iface.encodeFunctionData('create',[bytes32(metadata.authority_commitment),0]));
const vaultCode=compiled.contracts['Parano1dVault.sol'].Parano1dVault;
const vault={address:createAddressFromString(expectedAddress),iface:new Interface(vaultCode.abi),bytes:vaultCode.evm.deployedBytecode.object.length/2};
if((await vm.stateManager.getCode(vault.address)).length!==vault.bytes)throw Error('CREATE2 recovery');
await send('deposit_native_ETH',vault.address,'0x',10n**18n);
const amount=250_000_000_000_000_000n,expiry=blockNumber+100000n;
const [request]=await view(vault.address,vault.iface,'requestId',[recipient.toString(),amount,expiry]);
const [context]=await view(vault.address,vault.iface,'requestContext',[recipient.toString(),amount,expiry]);
const proofStarted=performance.now();
execFileSync(prover,[results,request.slice(2),network,context.slice(2)],{stdio:'inherit'});
const proverFixtureWallMs=performance.now()-proofStarted;
metadata=JSON.parse(await readFile(path.join(results,'native-proof.json'),'utf8'));
const expansionStarted=performance.now();
execFileSync('python3',[path.join(here,'prepare.py'),results],{stdio:'inherit',env:{...process.env,PYTHONPATH:pythonTools}});
const transportExpansionMs=performance.now()-expansionStarted;
const f=JSON.parse(await readFile(path.join(results,'evm-fixture.json'),'utf8'));
const b=f.base;
const base=[b.evaluations,b.roots,b.finalPolynomial,b.outputs,b.outerInverses,b.queryPowWitness];
const baseType=vault.iface.getFunction('authorize').inputs[3];
const jobMessage=AbiCoder.defaultAbiCoder().encode(['bytes32','bytes32',baseType],[request,context,base]);
const job='0x'+createHash('sha256').update(Buffer.from(jobMessage.slice(2),'hex')).digest('hex');
const jobOther=keccak256(jobMessage);
const recoveryEvents=[];
const query=q=>[q.leaves,q.paths,q.inverses];
const [challenges]=await view(checker.address,checker.iface,'transcript',[base,request,context]);
const refs=f.reference;
for(const name of ['alpha','zeta','pcsAlpha'])if(challenges[name]!==BigInt(refs[name]))throw Error('transcript '+name);
if(challenges.betas.some((x,i)=>x!==BigInt(refs.betas[i]))||challenges.indices.some((x,i)=>x!==BigInt(refs.indices[i])))throw Error('transcript arrays');
const balance=async address=>(await vm.stateManager.getAccount(address))?.balance||0n;
const snapshot=async()=>[await balance(vault.address),await balance(recipient),(await view(vault.address,vault.iface,'nonce',[]))[0]];
const before=await snapshot();
const checkUnchanged=async()=>{const now=await snapshot();if(now.some((x,i)=>x!==before[i]))throw Error('premature payout');};
let cacheBytes='0x';
const auth=(a,qs,who=recipient.toString(),cache=cacheBytes)=>vault.iface.encodeFunctionData('authorize',[who,a,expiry,base,qs,cache]);
await send('changed_amount_rejected',vault.address,auth(amount+1n,[]),0n,false);await checkUnchanged();
const invalidGrindingBase=[...base];invalidGrindingBase[5]=f.invalid_query_pow_witness;
await send('invalid_query_grinding_rejected',vault.address,vault.iface.encodeFunctionData('authorize',
  [recipient.toString(),amount,expiry,invalidGrindingBase,[],'0x']),0n,false);await checkUnchanged();
await send('begin_authorization',vault.address,auth(amount,[]));await checkUnchanged();
const [cache]=await view(checker.address,checker.iface,'prepareCache',[base,request,context]);
const cacheType=checker.iface.getFunction('prepareCache').outputs[0];
cacheBytes=AbiCoder.defaultAbiCoder().encode([cacheType],[cache]);
const corruptCache='0x'+(BigInt('0x'+cacheBytes.slice(2,66))^1n).toString(16).padStart(64,'0')+cacheBytes.slice(66);
await send('altered_cache_rejected',vault.address,auth(amount,[query(f.queries[0])],recipient.toString(),corruptCache),0n,false);await checkUnchanged();
const bad=structuredClone(f.queries[0]);const altered=Buffer.from(bad.leaves[0].slice(2),'hex');altered[0]^=1;bad.leaves[0]='0x'+altered.toString('hex');
await send('altered_proof_rejected',vault.address,auth(amount,[query(bad)]),0n,false);await checkUnchanged();
const wrong=f.queries.find((_,i)=>refs.indices[i]!==refs.indices[0]);
await send('query_skip_rejected',vault.address,auth(amount,[query(wrong)]),0n,false);await checkUnchanged();
for(let start=0;start<64;start+=groupSize){
  if(start===2*groupSize){
    const [progress]=await view(vault.address,vault.iface,'progress',[job,jobOther]);
    if(progress!==BigInt(start+1))throw Error('Relayer recovery progress');
    const [recoveredCache]=await view(checker.address,checker.iface,'prepareCache',[base,request,context]);
    const recoveredBytes=AbiCoder.defaultAbiCoder().encode([cacheType],[recoveredCache]);
    if(recoveredBytes!==cacheBytes)throw Error('Relayer recovery cache');
    const [storedHash]=await view(vault.address,vault.iface,'cacheHashes',[job,jobOther]);
    if(storedHash!==keccak256(recoveredBytes))throw Error('Relayer recovery authenticated cache');
    cacheBytes=recoveredBytes;
    recoveryEvents.push({case:'restart_after_lost_batch_response',accepted_queries:start,
      cache_reconstructed_from_public_proof:true});
  }
  await send(start+groupSize>=64?'verify_and_withdraw':'verify_query_batch',vault.address,auth(amount,f.queries.slice(start,start+groupSize).map(query)),0n,true,(start/groupSize)%2===1);
  if(start+groupSize<64)await checkUnchanged();
}
const after=await snapshot();
if(after[0]!==before[0]-amount||after[1]!==before[1]+amount||after[2]!==1n)throw Error('payout mismatch');
await send('replay_rejected',vault.address,auth(amount,[]),0n,false);
await send('changed_recipient_rejected',vault.address,auth(amount,[],'0x1111111111111111111111111111111111111111'),0n,false);
const successful=records.filter(r=>r.success&&['begin_authorization','prepare_query_cache','verify_query_batch','verify_and_withdraw'].includes(r.operation));
const summary={runtime:'@ethereumjs/vm 10.0.0',hardfork:'Prague',compiler:solc.version(),
  chain_id:chainId.toString(),local_block_number:blockNumber.toString(),expiry_block:expiry.toString(),
  gas_limit_per_transaction:16777216,code_size_limit:24576,verifier_code_bytes:checker.bytes,vault_code_bytes:vault.bytes,
  full_signed_transactions:true,positive_lifecycle_completed:true,native_transcript_matches:true,CREATE2_recovery_verified:true,independent_relayers_checked:true,
  altered_proof_rejected:true,altered_cache_rejected:true,query_skip_rejected:true,changed_amount_rejected:true,changed_recipient_rejected:true,replay_rejected:true,
  invalid_query_grinding_rejected:true,
  withdrawal_wei:amount.toString(),authorization_transactions:successful.length,
  query_batch_size:groupSize,
  authorization_gas:successful.reduce((s,r)=>s+r.gas,0),maximum_authorization_transaction_gas:Math.max(...successful.map(r=>r.gas)),
  local_positive_transaction_wall_ms:successful.reduce((s,r)=>s+r.local_transaction_wall_ms,0),
  local_vm_submit_ms:successful.reduce((s,r)=>s+r.local_vm_submit_ms,0),
  prover_fixture_wall_ms:proverFixtureWallMs,transport_expansion_ms:transportExpansionMs,
  relayer_restart_recovery_checked:true,recovery_events:recoveryEvents,
  latency_scope:'Local CPU time. Live inclusion, sequencing and finality require network measurement.',
  maximum_transaction_bytes:Math.max(...records.map(r=>r.transaction_bytes)),
  verifier:checker.address.toString(),factory:factory.address.toString(),vault:vault.address.toString(),request_id:request,records};
await writeFile(path.join(results,'evm-vault.json'),JSON.stringify(summary,null,2)+'\n');
console.log(JSON.stringify({...summary,records:undefined},null,2));

// Read-only Base fee quote for the signed local chain-8453 fixture.
// Uses eth_call and fee/header reads. No transaction is broadcast.
import {readFile,writeFile} from 'node:fs/promises';
import {pathToFileURL,fileURLToPath} from 'node:url';
import path from 'node:path';
import {createHash} from 'node:crypto';
const [toolDirectory,rpcOverride]=process.argv.slice(2);
const {Interface,Transaction,SigningKey,computeAddress}=await import(pathToFileURL(path.resolve(toolDirectory,'node_modules/ethers/lib.esm/index.js')).href);
const here=path.dirname(fileURLToPath(import.meta.url));
const directory=path.resolve(here,'../results/base');
const fixtureBytes=await readFile(path.join(directory,'evm-vault.json'));
const fixture=JSON.parse(fixtureBytes.toString('utf8'));
const prices=JSON.parse(await readFile(path.resolve(directory,'../market-quotes.json'),'utf8'));
if(fixture.chain_id!=='8453'||!fixture.positive_lifecycle_completed)throw Error('Complete local Base-chain fixture required');
const endpoints=rpcOverride?[rpcOverride]:['https://mainnet.base.org','https://base-rpc.publicnode.com'];
const oracle='0x420000000000000000000000000000000000000F';
const l1Block='0x4200000000000000000000000000000000000015';
const abi=new Interface([
 'function getL1Fee(bytes) view returns(uint256)',
 'function getL1FeeUpperBound(uint256) view returns(uint256)',
 'function getOperatorFee(uint256) view returns(uint256)',
 'function getL1GasUsed(bytes) view returns(uint256)',
 'function l1BaseFee() view returns(uint256)',
 'function blobBaseFee() view returns(uint256)',
 'function baseFeeScalar() view returns(uint32)',
 'function blobBaseFeeScalar() view returns(uint32)',
 'function isFjord() view returns(bool)',
 'function isIsthmus() view returns(bool)',
 'function isJovian() view returns(bool)',
 'function operatorFeeScalar() view returns(uint32)',
 'function operatorFeeConstant() view returns(uint64)',
 'function daFootprintGasScalar() view returns(uint16)'
]);
let id=0,source=endpoints[0];
const allowed=new Set(['eth_chainId','eth_getBlockByNumber','eth_gasPrice','eth_maxPriorityFeePerGas','eth_call']);
async function rpc(method,params){
 if(!allowed.has(method))throw Error('Read-only RPC method required');
 let last;
 for(const endpoint of [source,...endpoints.filter(x=>x!==source)]){
  try{
   const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','User-Agent':'Parano1dX-local-research/0.1'},body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params}),signal:AbortSignal.timeout(15000)});
   if(!response.ok)throw Error('HTTP '+response.status);
   const body=await response.json();if(body.error)throw Error(JSON.stringify(body.error));
   if(body.result===undefined)throw Error('Missing RPC result');source=endpoint;return body.result;
  }catch(e){last=e;}
 }
 throw last;
}
if(BigInt(await rpc('eth_chainId',[]))!==8453n)throw Error('Wrong network');
const head=await rpc('eth_getBlockByNumber',['latest',false]);
const block=head.number;
const observed=new Date().toISOString();
const gasPrice=BigInt(await rpc('eth_gasPrice',[]));
const priorityQuote=BigInt(await rpc('eth_maxPriorityFeePerGas',[]));
const baseFee=BigInt(head.baseFeePerGas);
if(gasPrice<baseFee)throw Error('Gas-price quote below pinned base fee');
async function call(name,args=[],address=oracle){
 const result=await rpc('eth_call',[{to:address,data:abi.encodeFunctionData(name,args)},block]);
 return abi.decodeFunctionResult(name,result)[0];
}
const parameters={};
for(const name of ['isFjord','isIsthmus','isJovian','l1BaseFee','blobBaseFee','baseFeeScalar','blobBaseFeeScalar']){
 const v=await call(name);parameters[name]=typeof v==='bigint'?v.toString():v;
}
for(const name of ['operatorFeeScalar','operatorFeeConstant','daFootprintGasScalar'])parameters[name]=(await call(name,[],l1Block)).toString();
const keys=[31,32].map(byte=>new SigningKey('0x'+byte.toString(16).padStart(2,'0').repeat(32)));
const keyByAddress=new Map(keys.map(k=>[computeAddress(k.publicKey).toLowerCase(),k]));
const authorizationNames=new Set(['begin_authorization','prepare_query_cache','verify_query_batch','verify_and_withdraw']);
const rows=fixture.records.filter(r=>r.success&&(authorizationNames.has(r.operation)||r.operation.startsWith('deploy_')||r.operation==='create_vault'));
const records=[];
for(const row of rows){
 const original=Transaction.from(row.transaction_hex);
 if(original.chainId!==8453n)throw Error('Non-Base serialized fixture');
 const tx=Transaction.from({type:0,chainId:8453n,nonce:original.nonce,to:original.to,data:original.data,value:original.value,gasLimit:original.gasLimit,gasPrice});
 const unsigned=tx.unsignedSerialized;
 const key=keyByAddress.get(row.fee_payer.toLowerCase());if(!key)throw Error('Unknown public fixture fee payer');
 tx.signature=key.sign(tx.unsignedHash);
 const l1Fee=await call('getL1Fee',[unsigned]);
 const operatorFee=await call('getOperatorFee',[BigInt(row.gas)]);
 const upper=await call('getL1FeeUpperBound',[BigInt((unsigned.length-2)/2)]);
 if(l1Fee>upper)throw Error('L1 fee exceeds oracle upper-bound fixture');
 const reportedL1Gas=await call('getL1GasUsed',[unsigned]);
 const footprint=reportedL1Gas*BigInt(parameters.daFootprintGasScalar)/16n;
 if(footprint>BigInt(head.gasLimit))throw Error('DA footprint exceeds pinned block capacity');
 const execution=BigInt(row.gas)*gasPrice;
 const record={operation:row.operation,scope:authorizationNames.has(row.operation)?'authorization':'setup',gas_used:row.gas,
  unsigned_transaction_bytes:(unsigned.length-2)/2,signed_transaction_bytes:(tx.serialized.length-2)/2,
  execution_fee_wei:execution.toString(),l1_data_fee_wei:l1Fee.toString(),operator_fee_wei:operatorFee.toString(),
  l1_upper_bound_wei:upper.toString(),total_fee_wei:(execution+l1Fee+operatorFee).toString(),
  fjord_estimated_l1_gas:reportedL1Gas.toString(),estimated_da_footprint_gas:footprint.toString(),
  unsigned_transaction_hex:unsigned,signed_transaction_hex:tx.serialized};
 records.push(record);
 console.log(JSON.stringify({...record,unsigned_transaction_hex:undefined,signed_transaction_hex:undefined}));
}
const sum=(rows,key)=>rows.reduce((n,r)=>n+BigInt(r[key]),0n);
const auth=records.filter(r=>r.scope==='authorization');
if(auth.length!==10)throw Error('Expected ten successful authorization transactions');
const total=sum(auth,'total_fee_wei');
const execution=sum(auth,'execution_fee_wei');
const noTipExecution=BigInt(fixture.authorization_gas)*baseFee;
const result={network:'Base Mainnet',chain_id:8453,quote_type:'Local chain-8453 execution gas repriced with block-pinned live Base fee oracles',
 positive_local_lifecycle_completed:true,broadcast_transactions:0,rpc_source:source,quoted_at_utc:observed,
 local_fixture_sha256:createHash('sha256').update(fixtureBytes).digest('hex'),
 block:{number:parseInt(head.number,16),hex:head.number,hash:head.hash,timestamp:parseInt(head.timestamp,16),base_fee_wei:baseFee.toString(),gas_limit:parseInt(head.gasLimit,16),extra_data:head.extraData},
 suggested_gas_price_wei:gasPrice.toString(),included_priority_fee_wei:(gasPrice-baseFee).toString(),rpc_priority_quote_wei:priorityQuote.toString(),
 oracle_address:oracle,oracle_parameters:parameters,eth_usd:prices.eth_usd,asset_quote_utc:prices.asset_quote_at_utc,
 authorization_transactions:auth.length,authorization_gas:fixture.authorization_gas,
 execution_fee_wei:execution.toString(),execution_fee_usd:Number(execution)/1e18*prices.eth_usd,
 l1_data_fee_wei:sum(auth,'l1_data_fee_wei').toString(),l1_data_fee_usd:Number(sum(auth,'l1_data_fee_wei'))/1e18*prices.eth_usd,
 operator_fee_wei:sum(auth,'operator_fee_wei').toString(),
 total_fee_wei:total.toString(),total_fee_ETH:Number(total)/1e18,total_fee_USD:Number(total)/1e18*prices.eth_usd,
 no_tip_execution_fee_wei:noTipExecution.toString(),no_tip_execution_fee_usd:Number(noTipExecution)/1e18*prices.eth_usd,
 setup_records:records.filter(r=>r.scope==='setup').map(({unsigned_transaction_hex,signed_transaction_hex,...r})=>r),
 scope:'One complete successful authorization and native withdrawal. Shared deployment, vault creation and rejected test cases are separate. L1 fee uses unsigned RLP because the oracle adds signature padding. Execution gas is measured locally, not a mainnet transaction receipt.',
 sources:['https://docs.base.org/specifications/transactions/network-fees','https://docs.base.org/specifications/transactions/throughput-and-limits','https://raw.githubusercontent.com/ethereum-optimism/optimism/develop/packages/contracts-bedrock/src/L2/GasPriceOracle.sol'],records};
await writeFile(path.join(directory,'fee-quote.json'),JSON.stringify(result,null,2)+'\n');
prices.L2_rpc_quotes={...prices.L2_rpc_quotes,[source]:{chain_id:8453,quoted_at_utc:observed,quote_file:'base/fee-quote.json'}};
await writeFile(path.resolve(directory,'../market-quotes.json'),JSON.stringify(prices,null,2)+'\n');
console.log(JSON.stringify({...result,records:undefined,setup_records:undefined},null,2));

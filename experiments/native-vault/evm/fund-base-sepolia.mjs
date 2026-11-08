// Wait for free test ETH on Base Sepolia or Ethereum Sepolia, then run the test.
// The only optional funding transfer is Sepolia -> Base Sepolia standard bridge.
import {readFile,writeFile,stat,mkdir} from 'node:fs/promises';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import path from 'node:path';
const [tools,prover,pythonTools,keys]=process.argv.slice(2);
const {Wallet,Interface,keccak256}=await import(pathToFileURL(path.resolve(tools,'node_modules/ethers/lib.esm/index.js')).href);
const file=path.resolve(keys,'relayer.json');if((await stat(file)).mode&0o077)throw Error('Owner-only fee key required');
const saved=JSON.parse(await readFile(file,'utf8'));if(saved.chainId!==84532)throw Error('Test-only fee key required');
const payer=new Wallet(saved.privateKey);if(payer.address!==saved.address)throw Error('Fee address mismatch');
const base='https://sepolia.base.org',l1='https://ethereum-sepolia-rpc.publicnode.com';
const bridge='0xfd0Bf71F60660E2f608ed56e1659C450eB113120';
const otherBridge='0x4200000000000000000000000000000000000010';
const abi=new Interface(['function depositETHTo(address,uint32,bytes) payable','function otherBridge() view returns(address)']);
const here=path.dirname(fileURLToPath(import.meta.url));
const directory=path.resolve(here,'../results/base-sepolia/funding');await mkdir(directory,{recursive:true});
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const json=x=>JSON.stringify(x,(_,v)=>typeof v==='bigint'?v.toString():v,2)+'\n';
let id=0;
async function rpc(endpoint,method,params=[]){
 const response=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','User-Agent':'Parano1dX-testnet-funding/0.1'},
  body:JSON.stringify({jsonrpc:'2.0',id:++id,method,params}),signal:AbortSignal.timeout(20000)});
 if(!response.ok)throw Error('HTTP '+response.status);
 const body=await response.json();if(body.error)throw Error(body.error.message);return body.result;
}
async function networks(){
 if(BigInt(await rpc(base,'eth_chainId'))!==84532n||BigInt(await rpc(l1,'eth_chainId'))!==11155111n)throw Error('Sepolia networks required');
}
await networks();
let bridged=false;
try{await stat(path.join(directory,'bridge.json'));bridged=true;}catch(e){if(e.code!=='ENOENT')throw e;}
async function bridgeTestETH(balance){
 await networks();
 const code=await rpc(l1,'eth_getCode',[bridge,'latest']);if(code==='0x')throw Error('Missing standard bridge code');
 const output=await rpc(l1,'eth_call',[{to:bridge,data:abi.encodeFunctionData('otherBridge')},'latest']);
 if(abi.decodeFunctionResult('otherBridge',output)[0].toLowerCase()!==otherBridge.toLowerCase())throw Error('Unexpected L2 bridge');
 const data=abi.encodeFunctionData('depositETHTo',[payer.address,200000,'0x']);
 const quotedPrice=BigInt(await rpc(l1,'eth_gasPrice'));
 const gasPrice=quotedPrice*2n;
 if(gasPrice>100_000_000_000n)throw Error('Unexpected Sepolia gas quote');
 const estimate=BigInt(await rpc(l1,'eth_estimateGas',[{from:payer.address,to:bridge,data,value:'0x38d7ea4c68000'}]));
 const gasLimit=estimate*13n/10n;if(gasLimit>2000000n)throw Error('Unexpected bridge gas estimate');
 const usable=balance-gasLimit*gasPrice*2n;
 const value=usable<5_000_000_000_000_000n?usable:5_000_000_000_000_000n;
 if(value<1_000_000_000_000_000n)return false;
 const nonce=Number(BigInt(await rpc(l1,'eth_getTransactionCount',[payer.address,'pending'])));
 const tx={type:0,chainId:11155111n,nonce,to:bridge,data,value,gasPrice,gasLimit};
 await networks();const raw=await payer.signTransaction(tx),hash=keccak256(raw);
 const record={source_chain_id:11155111,destination_chain_id:84532,source_rpc:l1,destination_rpc:base,bridge,
  bridge_source:'https://github.com/wevm/viem/blob/main/src/chains/definitions/baseSepolia.ts',
  sender:payer.address,recipient:payer.address,value_wei:value.toString(),gas_limit:gasLimit.toString(),
  gas_price_wei:gasPrice.toString(),transaction_hex:raw,transaction_hash:hash,submitted_at_utc:new Date().toISOString(),real_assets_used:false};
 bridged=true;
 await writeFile(path.join(directory,'bridge.json'),json(record));
 const result=await rpc(l1,'eth_sendRawTransaction',[raw]);if(result!==hash)throw Error('Bridge transaction hash mismatch');
 console.log(json({event:'test_ETH_bridge_submitted',hash,value_wei:value.toString()}).trim());
 for(let i=0;i<120;i++){
  const receipt=await rpc(l1,'eth_getTransactionReceipt',[hash]);
  if(receipt){record.receipt=receipt;await writeFile(path.join(directory,'bridge.json'),json(record));if(receipt.status!=='0x1')throw Error('Test bridge reverted');return true;}
  await pause(5000);
 }
 throw Error('Bridge L1 receipt deadline');
}
for(let i=0;i<480;i++){
 try{
  const balance=BigInt(await rpc(base,'eth_getBalance',[payer.address,'latest']));
  if(balance>=1_000_000_000_000_000n){
   console.log(json({event:'Base_Sepolia_funded',balance_wei:balance.toString()}).trim());
   execFileSync(process.execPath,[path.join(here,'test-base-sepolia.mjs'),tools,prover,pythonTools,keys,'--run','spare-public-normal-1'],{stdio:'inherit'});
   process.exit(0);
  }
  const l1Balance=BigInt(await rpc(l1,'eth_getBalance',[payer.address,'latest']));
  if(i%4===0)console.log(json({event:'waiting_for_free_test_ETH',address:payer.address,base_sepolia_balance_wei:balance.toString(),ethereum_sepolia_balance_wei:l1Balance.toString()}).trim());
  if(!bridged&&l1Balance>=2_000_000_000_000_000n)bridged=await bridgeTestETH(l1Balance);
 }catch(error){
  console.log(json({event:'funding_worker_error',message:error.message.slice(0,300)}).trim());
  // A submitted bridge and an executed benchmark are resumed deliberately.
  if(bridged||error.status!==undefined)throw error;
 }
 await pause(15000);
}
throw Error('Free test-ETH funding deadline');

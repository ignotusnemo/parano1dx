import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';

const [toolDir, fixtureDirectory] = process.argv.slice(2);
const load = relative => import(pathToFileURL(path.join(toolDir, 'node_modules', relative)).href);
const {default: solc} = await load('solc/index.js');
const {Interface} = await load('ethers/lib.esm/index.js');
const {createVM} = await load('@ethereumjs/vm/dist/esm/index.js');
const {Account, createAddressFromString, hexToBytes, bytesToHex} = await load('@ethereumjs/util/dist/esm/index.js');
const here = path.dirname(fileURLToPath(import.meta.url));
const sources = {};
for (const name of ['VField.sol', 'VVerifier.sol', 'VParameters.sol', 'VSampler.sol']) {
  sources[name] = {content: await readFile(path.join(here, name), 'utf8')};
}
sources['ArithmeticProbe.sol'] = {content: `pragma solidity ^0.8.30;
import "./VVerifier.sol";
contract ArithmeticProbe is VVerifier {
    function externalLayer(uint256[24] memory v) external pure returns(uint256[24] memory){return externalLinear(v);}
    function internalLayer(uint256[24] memory v) external pure returns(uint256[24] memory){return internalLinear(v);}
    function combine(uint256[268] memory p,bytes calldata row,uint256 start,uint256 width) external pure returns(uint256){
        require(width>0&&width<=48&&start+width<=268&&row.length==4*width);
        return combination(p,row,0,start,width);
    }
    function equalRoot(bytes memory a,bytes memory b) external pure returns(bool){return VH.equal(a,b);}
}`};
const output = JSON.parse(solc.compile(JSON.stringify({language: 'Solidity', sources, settings: {
  optimizer: {enabled: true, runs: 200}, viaIR: true, evmVersion: 'cancun',
  outputSelection: {'*': {'*': ['abi', 'evm.deployedBytecode.object']}}
}})));
const errors = output.errors?.filter(e => e.severity === 'error') || [];
if (errors.length) throw Error(errors.map(e => e.formattedMessage).join('\n'));
const probe = output.contracts['ArithmeticProbe.sol'].ArithmeticProbe;
const vm = await createVM();
const address = createAddressFromString('0x0000000000000000000000000000000000000123');
await vm.stateManager.putAccount(address, new Account());
await vm.stateManager.putCode(address, hexToBytes('0x' + probe.evm.deployedBytecode.object));
const iface = new Interface(probe.abi);
async function call(name, args) {
  const result = await vm.evm.runCall({to: address, data: hexToBytes(iface.encodeFunctionData(name, args)), gasLimit: 16000000n});
  if (result.execResult.exceptionError) throw Error(name + ': ' + result.execResult.exceptionError.error);
  return iface.decodeFunctionResult(name, bytesToHex(result.execResult.returnValue))[0];
}
const fixture = JSON.parse(await readFile(path.join(fixtureDirectory, 'evm-export.json'), 'utf8'));
const P = 2130706433n, ONE = 33554430n, RI = 1057030144n;
const pack = lanes => lanes.reduce((sum, value, i) => sum | (BigInt(value) << BigInt(32 * i)), 0n);
const unpack = value => Array.from({length: 8}, (_, i) => (value >> BigInt(32 * i)) & 0xffffffffn);
function randomWord(i) {
  const bytes = createHash('sha256').update('Parano1dX arithmetic check').update(String(i)).digest();
  return pack(Array.from({length: 8}, (_, j) => BigInt(bytes.readUInt32LE(4 * j)) % P));
}
let matrixCases = 0;
for (const kind of ['external', 'internal']) {
  const matrix = fixture[kind + '_matrix_columns_raw'].map(column => column.map(BigInt));
  for (let i = 0; i < 28; ++i) {
    const values = i < 24 ? Array.from({length: 24}, (_, j) => j === i ? ONE : 0n)
      : Array.from({length: 24}, (_, j) => randomWord(i * 24 + j));
    const expected = Array.from({length: 24}, (_, row) => pack(Array.from({length: 8}, (_, lane) =>
      values.reduce((sum, v, col) => sum + unpack(v)[lane] * matrix[col][row], 0n) * RI % P)));
    const actual = await call(kind + 'Layer', [values]);
    if (actual.some((v, j) => v !== expected[j])) throw Error(kind + ' matrix correspondence');
    ++matrixCases;
  }
}
let combinationCases = 0;
for (const width of [16, 27, 48]) for (const pattern of ['zero', 'maximum', 'random']) {
  const powers = Array.from({length: 268}, (_, i) => pattern === 'zero' ? 0n
    : pattern === 'maximum' ? pack(Array(8).fill(P - 1n)) : randomWord(i));
  const values = Array.from({length: width}, (_, i) => pattern === 'zero' ? 0n
    : pattern === 'maximum' ? P - 1n : unpack(randomWord(1000 + i))[0]);
  const bytes = Buffer.alloc(width * 4);
  values.forEach((v, i) => bytes.writeUInt32LE(Number(v), 4 * i));
  const start = 112;
  const expected = pack(Array.from({length: 8}, (_, lane) =>
    values.reduce((sum, v, i) => sum + unpack(powers[start + i])[lane] * v, 0n) * RI % P));
  if (await call('combine', [powers, bytes, start, width]) !== expected) throw Error('deferred reduction correspondence');
  ++combinationCases;
}
const root = Buffer.concat([createHash('sha256').update('first').digest(), createHash('sha256').update('second').digest()]);
if (!await call('equalRoot', [root, root])) throw Error('equal root');
for (const position of [0, 31, 32, 63]) {
  const changed = Buffer.from(root); changed[position] ^= 1;
  if (await call('equalRoot', [root, changed])) throw Error('changed root half');
}
for (const length of [0, 32, 63, 65]) if (await call('equalRoot', [root, Buffer.alloc(length)])) throw Error('root length');
const result = {matrix_basis_and_extension_cases: matrixCases, deferred_reduction_cases: combinationCases,
  exact_root_cases: 9, all_checks_passed: true,
  accumulation_upper_bound: (48n * (P - 1n) ** 2n * RI).toString(),
  accumulator_fits_uint256: 48n * (P - 1n) ** 2n * RI < 1n << 256n};
await writeFile(path.join(fixtureDirectory, 'arithmetic-checks.json'), JSON.stringify(result, null, 2) + '\n');
console.log(JSON.stringify(result));

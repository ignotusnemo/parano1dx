import {readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const dir=path.join(root,'research/security');
const i=process.argv.indexOf('--katex');
if(i<0||!process.argv[i+1])throw Error('Usage: node tools/build_security_report.mjs --katex PATH_TO_KATEX_MJS');
const modulePath=path.resolve(process.argv[i+1]);const imported=await import(pathToFileURL(modulePath).href);const katex=imported.default??imported;
const readJSON=async p=>JSON.parse(await readFile(p,'utf8'));
const data=await readJSON(path.join(dir,'security-evaluation.json'));const nist=data.nist;
const assessment=await readJSON(path.join(dir,'nist-resource-assessment.json'));
const circuits=await readJSON(path.join(dir,'hash-circuit-checks.json'));
const circuitRows=assessment.native_circuit_audit.projection_rows;
const minimumLayout=(fn,projection,construction)=>circuitRows.filter(r=>r.function===fn&&r.projection===projection&&(!construction||r.construction===construction)).reduce((a,b)=>a.conservative_gate_depth<b.conservative_gate_depth?a:b);
const phase=circuits.minimum_sampled_phase_data;
const layoutRows=[
 ['Keccak-256, full digest',minimumLayout('Keccak256','full256')],
 ['Keccak-256, twelve grind bits',minimumLayout('Keccak256','grind12')],
 ['Keccak-256, one-bit XOR output',minimumLayout('Keccak256','last_byte_low_bit')],
 ['Keccak-256, one-bit phase data',{AND:phase.AND,XOR:phase.XOR,AND_depth:phase.AND_depth,conservative_gate_depth:phase.data_only_conservative_gate_depth}],
 ['SHA-256, one-bit ripple-adder output',minimumLayout('SHA256','last_byte_low_bit','ripple_majority')]
];
function decimal(x,digits,roundUp=false){const scale=10n**BigInt(digits),n=BigInt(x.numerator)*scale,d=BigInt(x.denominator);const v=(n+(roundUp?d-1n:0n))/d;const s=v.toString().padStart(digits+1,'0');return`${s.slice(0,-digits)}.${s.slice(-digits)}`;}
const idealBound=decimal(nist.maximum_ideal_bound,9,true);
const primitiveMargin=decimal(nist.primitive_advantage_margin,9);
const price=nist.batch_response_gate_depth_condition;
const good=data.public_coin_ledger.source_good_positions;
const result=path.join(root,'experiments/native-vault/results');
const evm=await readJSON(path.join(result,'optimized-evm/evm-vault.json'));
const sol=await readJSON(path.join(result,'optimized-solana/solana-vault.json'));
const wallet=await readJSON(path.join(result,'profile-optimization/optimized-prover.json'));
const comparison=(await readJSON(path.join(result,'profile-optimization/summary.json'))).published_comparison;
const publicRuns=await readJSON(path.join(result,'public-optimized-summary.json'));
const publicBase=publicRuns.base_sepolia;
const publicSolana=publicRuns.solana_devnet;
const esc=s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');
function upper(x,digits=9){const n=BigInt(x.numerator),d=BigInt(x.denominator);if(n===0n)return'0';let exponent=n.toString().length-d.toString().length;while(exponent>=0?n<d*10n**BigInt(exponent):n*10n**BigInt(-exponent)<d)--exponent;const shift=digits-1-exponent;const a=shift>=0?n*10n**BigInt(shift):n;const b=shift>=0?d:d*10n**BigInt(-shift);let c=(a+b-1n)/b;if(c===10n**BigInt(digits)){c/=10n;++exponent}const s=c.toString().padStart(digits,'0');return`${s[0]}.${s.slice(1)}e${exponent>=0?'+':''}${exponent}`;}
const equation=s=>`<div class="equation">${katex.renderToString(s,{displayMode:true,throwOnError:true,output:'htmlAndMathml'})}</div>`;
let template=await readFile(path.join(dir,'report-head.html'),'utf8');let head=template.slice(0,template.indexOf('</head>')+7);
head=head.replace('<title>Native-Asset Vault Authorization: Security Report</title>','<title>Native-Asset Authorization: Quantum Security and Resource Bound</title>');
let html=head+`<body><main>
<header><div class="topline"><span class="label">Parano1dX · Research</span><a class="screen-only" href="papers/native-vault-security-report.pdf">Download PDF</a></div>
<h1>Native-Asset Authorization<br>Quantum Security and Resource Bound</h1><p class="meta">Ignotus Nemo · dev@parano1d.org · 9 November 2026</p>
<p>A native quantum chosen-request reduction, a concrete AES-128 resource assessment and implementations for EVM and Solana vaults.</p></header>
<nav><a href="#result">Result</a><a href="#construction">Construction</a><a href="#resources">AES-128 comparison</a><a href="#measurements">Implementation</a><a href="#proofs">Proofs</a></nav>
<section id="result"><h2>1. Result and conditions</h2>
<p>Fresh unauthorized release reduces to the fixed authority-preimage game, the derivation and private-generator games, and an explicit native proof-loss bound. The simulator answers adaptive classical authorization requests. The extractor uses the same quantum-hash experiment and one final database measurement.</p>
<div class="scope"><strong>Preliminary NIST Category 1 resource assessment</strong>At the AES-128 reference budgets, the complete ideal proof-loss envelope is at most ${idealBound}. The corollary uses the batch response-price condition c ≥ ${price.toLocaleString('en-US')} gate-depth and a combined authority-preimage, derivation and private-generator advantage below ${primitiveMargin}. Published circuits and native fixed-prefix implementations calibrate the selected reference price in Section 3.</div>
<table><thead><tr><th>Quantity</th><th>Result</th></tr></thead><tbody>
<tr><td>Code domain and FRI checks</td><td>4,096 positions, 64 distinct checks</td></tr>
<tr><td>Extension degree and committed degree</td><td>8 and 256</td></tr>
<tr><td>Joint native query density</td><td>2<sup>−${data.native_grinding_ledger.query_group_density.negative_log2.toFixed(5)}</sup></td></tr>
<tr><td>Finite field-error density</td><td>2<sup>−${data.native_grinding_ledger.field_density.negative_log2.toFixed(5)}</sup></td></tr>
<tr><td>Native proof loss at T = 2²⁴</td><td>≤ ${upper(data.native_quantum_authorization.at_query_budget_bits['24'].combined)}</td></tr>
<tr><td>Native proof loss at T = 2⁶⁴</td><td>≤ ${upper(data.native_quantum_authorization.at_query_budget_bits['64'].combined)}</td></tr>
<tr><td>Quantum AES-128 reference</td><td>G·D = 2¹⁷⁰, ideal success ≤ ${upper(nist.maximum_ideal_bound)}</td></tr>
<tr><td>Classical reference at unit hash-call price</td><td>2¹⁴³ gates, ideal success ≤ ${upper(nist.classical_bound_even_at_unit_hash_price)}</td></tr>
</tbody></table>
${equation(String.raw`\Pr[\mathsf{ReleaseForge}]\le\operatorname{Adv}_{\mathrm{pre}}(\mathcal B)+\varepsilon_{\mathrm{der}}+\varepsilon_{\mathrm{rng}}+L(G,D,S,T).`)}
<p>The preimage adversary includes the complete deterministic source-decoding and candidate-validation work. The host supplies authenticated execution, protected persistent state and the canonical nonce policy. The exact primitive and host games appear in Appendix A.</p></section>
<section id="construction"><h2>2. Construction and proof geometry</h2>
<p>A Parano1d secret derives an authority branch for each network and account index. A 24-element Poseidon2 permutation with eight full and 26 partial rounds maps fourteen private field elements and ten fixed capacity elements to twelve public outputs. Their 32-byte commitment identifies the vault authority.</p>
<p>The request is bound by SHA-256 and Keccak-256 on the same canonical encoding. One component enters the AIR. The second enters the transcript's initial state. Every Merkle root compares the complete 64-byte hybrid digest. The EVM job and cache, and the Solana base and request, retain both binding components.</p>
<p>The 128-row logical trace executes on its odd rows. Its 64 free logical rows and 128 hiding-PCS rows supply 192 private state-mask coordinates. Main transport uses at most 144. Quotient transport uses 72 of 128. The source domain remains 4,096 positions.</p>
<p>The query vector is a 64-element subset. One 512-bit response contains the twelve-bit grinding predicate and a 500-bit rank source. Cofactor reduction and colexicographic unranking select the subset. The exact finite source threshold is ${good} good positions.</p>
${equation(String.raw`M=\binom{4096}{64},\qquad\kappa_q=\frac{\lceil2^{500}/M\rceil\binom{${good}}{64}}{2^{512}}.`)}
${equation(String.raw`\kappa_f=\frac{\lceil2^{512}/p^8\rceil N_f}{2^{512}},\qquad\kappa=\kappa_q+\kappa_f.`)}
<p>Each extension challenge likewise uses one full response, mapped to eight radix-p digits. The native compiler can therefore apply its one-local transition bound to the complete response. Five finite Reed–Solomon certificates and the exact fold identities supply the source ledger.</p></section>
<section id="resources"><h2>3. AES-128 resource comparison</h2>
<p>NIST Category 1 uses AES-128 key search as its reference. The quantum calculation evaluates G·D = 2¹⁷⁰ at depths 2⁴⁰, 2⁶⁴ and 2⁹⁶. The classical calculation uses 2¹⁴³ gates. At most 2⁶⁴ classical authorization requests are included. <a href="${esc(data.references.nist)}">NIST security evaluation criteria</a>.</p>
<p>For each coherent batch, A is its logical gate count, δ its depth and k its number of charged responses. The minimum-cost condition is k·c ≤ A·δ with c ≥ ${price.toLocaleString('en-US')} gate-depth. It applies to the cheaper hash component, including parallel execution and workspace reuse. The conservative adversarial physical-call count is bounded by G.</p>
<p>The resource assessment evaluates published direct-call layouts and native fixed-prefix circuits. Its native counting convention charges each live XOR and AND once and uses AND depth as an optimistic depth charge for node-by-node realizations. The all-batch contract states the condition for applying the theorem to other implementations. The exact evaluator gives a sufficient response price of ${Number(nist.minimum_sufficient_price_for_ideal_bound_below_half).toLocaleString('en-US')} gate-depth for the ideal envelope below one half.</p>
${equation(String.raw`L=\varepsilon_{\mathrm{sim}}+\left(\sqrt{\frac{10GD\kappa}{c(1-\beta/N)}}+E_{\mathrm{protect}}+E_{\mathrm{updates}}+E_{\mathrm{record}}\right)^2.`)}
<table><thead><tr><th>Depth D</th><th>Gates G</th><th>Complete ideal upper bound</th></tr></thead><tbody>
${nist.quantum_rows.map(r=>`<tr><td>2<sup>${r.depth_bits}</sup></td><td>2<sup>${170-r.depth_bits}</sup></td><td>${upper(r.ideal_bound)}</td></tr>`).join('')}
</tbody></table>
${equation(String.raw`GD_{1/2}^{\mathrm{main}}=\frac{c}{20\kappa}\simeq2^{${nist.main_half_gate_depth_floor_bits.toFixed(9)}}.`)}
<p>The reference-budget rows include simulation, global prefix protection, retained updates and terminal recording. The dominant-term floor describes the main term. The full corollary uses the complete reference-budget envelope and the primitive-advantage margin in Section 1.</p>
<table><thead><tr><th>Batch response price c</th><th>Ideal upper bound at G·D = 2¹⁷⁰</th></tr></thead><tbody>
${[1,2**19,2**20,2**24].map(c=>`<tr><td>${c.toLocaleString('en-US')}</td><td>${upper(nist.price_sensitivity[String(c)])}</td></tr>`).join('')}
</tbody></table>
<p>The counted-query theorem gives ideal proof loss at most ${upper(data.native_quantum_authorization.at_query_budget_bits['64'].combined)} at T = 2⁶⁴ physical hash calls. It uses the query budget directly. The gate-depth corollary additionally uses the batch response-price condition.</p>
<h3>Native circuit resource assessment</h3>
<p>The shortest candidate is a 64-byte transcript seal followed by a canonical four-byte field nonce. The first SHA-256 compression state is cached. The remaining compression includes its message schedule and digest feed-forward. Keccak-256 uses one padded 24-round permutation. The circuit checker specializes three fixed classical prefixes and 31 variable nonce bits, then removes unused output cones.</p>
<table><thead><tr><th>Lowest sampled layout</th><th>Counted data operations</th><th>Optimistic G·D</th></tr></thead><tbody>
${layoutRows.map(([name,r])=>`<tr><td>${esc(name)}</td><td>${r.AND.toLocaleString('en-US')} AND + ${r.XOR.toLocaleString('en-US')} XOR<br>AND depth ${r.AND_depth}</td><td>${r.conservative_gate_depth.toLocaleString('en-US')}</td></tr>`).join('')}
</tbody></table>
<p>The one-bit phase implementation expands the output XOR cone into a parity frontier. Its ${phase.data_only_conservative_gate_depth.toLocaleString('en-US')} data product omits the CZ and Z phases, workspace cleanup and fanout. This optimistic same-layout charge is ${(phase.data_only_conservative_gate_depth/price).toFixed(3)} times the selected reference price. Each row describes the sampled construction and its stated counting model.</p>
<p>The symbolic Keccak circuit reproduces 38,400 AND operations at AND depth 24. The four-T temporary-AND mapping agrees with the published clean-XOR construction, including measured cleanup. Native digests and projected outputs agree with SHA-256 and Keccak-256 reference implementations. <a href="https://arxiv.org/abs/2006.03845">Häner and Soeken</a>, <a href="https://arxiv.org/abs/1908.01609">Meuli et al.</a>.</p>
<p>Classically prepared tables are charged during construction. The assessment separately records coherent prefix preparation, partial outputs, shared computation and quantum-memory strategies. Its <a href="research/security/nist-resource-assessment.txt">resource model</a>, <a href="research/security/quantum-circuit-resources.txt">published circuit ledger</a> and <a href="research/security/hash-circuit-checks.json">native circuit counts</a> specify the evaluated layouts and the cryptanalytic conditions for applying the Category 1 comparison.</p></section>
<section id="measurements"><h2>4. Implementations and public withdrawals</h2>
<h3>Local execution</h3>
<p>Both vault implementations complete native-asset deposits and withdrawals with the selected profile. The lifecycle checks cover altered inputs, changed recipients and amounts, stale requests, replay, independent relayers and recovery after a lost response.</p>
<table><thead><tr><th>Measurement</th><th>EVM</th><th>Solana v1</th></tr></thead><tbody>
<tr><td>Authorization transactions</td><td>${evm.authorization_transactions}</td><td>${sol.authorization_transactions}</td></tr>
<tr><td>Execution charge</td><td>${evm.authorization_gas.toLocaleString('en-US')} gas total</td><td>${sol.maximum_verification_transaction_CU.toLocaleString('en-US')} CU maximum</td></tr>
<tr><td>Maximum EVM transaction</td><td>${evm.maximum_authorization_transaction_gas.toLocaleString('en-US')} gas</td><td>1,400,000 CU limit</td></tr>
<tr><td>Ordered verification transactions</td><td>7 including initialization</td><td>${sol.verification_transactions}</td></tr>
<tr><td>Temporary proof-account reserve</td><td>Contract state</td><td>${(sol.proof_buffer_rent_lamports/1e9).toFixed(6)} SOL, fully refunded</td></tr>
</tbody></table>
<p>The current wallet run measured ${wallet.proving_median_ms.toFixed(2)} ms median proving across ${wallet.measured_proofs} fresh proofs after ${wallet.warmup_proofs} warmups, on an Intel Core i7-1365U laptop. Background load and temperature were not controlled.</p>
<h3>Comparison with the published research</h3>
<p>The <a href="${esc(comparison.article.url)}">8 November article</a> supplies the published local-withdrawal baseline. The current column contains the selected local profile measured on 9 November.</p>
<table class="published-comparison"><thead><tr><th>Measurement</th><th>Published</th><th>Current</th></tr></thead><tbody>
${comparison.rows.map(r=>`<tr><td>${esc(r.measurement)}</td><td>${esc(r.published)}</td><td>${esc(r.current)}</td></tr>`).join('')}
</tbody></table>
<p>EVM execution uses ${comparison.evm_gas_reduction_percent.toFixed(1)}% less gas and three fewer transactions. Solana uses two fewer ordered verification transactions. Its complete fixture uses four more transactions and a higher peak CU charge.</p>
<p>The published wallet values are individual CPU samples. The current value is a nine-proof median on an Intel Core i7-1365U laptop. Both measure proof generation with public preprocessing and trace construction timed separately.</p>
<p>Signed Solana v1 wires are checked separately from the emulator's instruction replay. Solana accumulates each subset-rank term in its existing verification windows. Final rank equality is enforced before payout. This preserves the native acceptance conjunction while keeping preparation within the CU limit.</p>
<h3>Public testnet execution</h3>
<p>The selected profile completed withdrawals on Base Sepolia and Solana Devnet. An independent RPC audit checked signed transactions, deployed code, all 64 query positions, request binding and recipient balances. Each live runner also checked nonce consumption. Both Solana cases returned their complete temporary-account reserve.</p>
<div class="table-scroll"><table><thead><tr><th>Observed run</th><th>Transactions</th><th>Execution charge</th><th>Confirmed withdrawal</th></tr></thead><tbody>
<tr><td>Base Sepolia</td><td>${publicBase.authorization_transactions}</td><td>${publicBase.authorization_gas.toLocaleString('en-US')} gas total</td><td>${publicBase.confirmed_s.toFixed(2)} s</td></tr>
${publicSolana.map(r=>`<tr><td>Solana Devnet v1${r.fault_injection_enabled?', packet loss and reordering':''}</td><td>${r.unique_authorization_transactions}</td><td>${r.maximum_verification_CU.toLocaleString('en-US')} CU maximum</td><td>${r.withdrawal_confirmed_s.toFixed(2)} s</td></tr>`).join('')}
</tbody></table></div>
<p>These are individual network observations from a QEMU Virtual CPU version 2.5+ relayer host. The timer starts before proof preparation and ends at observed withdrawal confirmation. Deployment and deposits precede it. The public proofs took ${publicSolana[1].wallet_proving_ms.toFixed(2)} to ${publicBase.wallet_proving_ms.toFixed(2)} ms on that host. The local laptop median above is a separate measurement.</p>
<p>Solana delivery uses direct validator TPU QUIC with four concurrent upload workers and twelve ordered verification windows. The faulted run recovered a deliberately missing chunk after packet reordering. Its network fee was ${(publicSolana[1].actual_network_fee_lamports/1e9).toFixed(6)} test SOL, versus ${(publicSolana[0].actual_network_fee_lamports/1e9).toFixed(6)} test SOL in the normal run. The normal temporary reserve was ${(publicSolana[0].temporary_reserve_lamports/1e9).toFixed(8)} test SOL and was fully returned.</p>
<p>The Base total authorization fee was ${(Number(publicBase.authorization_fee_wei)/1e18).toFixed(12)} test ETH. Its receipts record execution and L1 data charges separately, with zero operator fee. Confirmation and finality observations retain their network-specific labels in the evidence. The Solana audit checked finalized data for every captured transaction.</p>
<p>Public withdrawals: <a href="${esc(publicBase.withdrawal_explorer_url)}">Base Sepolia</a>, <a href="${esc(publicSolana[0].withdrawal_explorer_url)}">Solana Devnet normal</a> and <a href="${esc(publicSolana[1].withdrawal_explorer_url)}">Solana Devnet with packet loss</a>. The <a href="experiments/native-vault/results/public-optimized-summary.json">public-run summary</a> binds these values to the raw receipts and independent audits by SHA-256.</p></section>
<section><h2>5. Reproduction</h2><p>The reading report embeds all proof texts below. Exact arithmetic and source fingerprints are in <a href="research/security/security-evaluation.json">security-evaluation.json</a>. The finite witnesses are in <a href="research/security/rs-certificate.json">rs-certificate.json</a>. Code and execution fixtures are under <a href="experiments/native-vault/">experiments/native-vault</a>. The circuit checker uses PyCryptodome. The <a href="research/security/README.txt">reproduction guide</a> lists dependencies and additional transcript checks.</p>
<pre>python3 research/security/check_rs_certificate.py
python3 research/security/check_profile.py
python3 research/security/check_mask_transport.py
python3 research/security/check_sampler.py
python3 research/security/check_hash_circuits.py
python3 research/security/evaluate_security.py
python3 tools/summarize_optimization.py
python3 tools/summarize_public_runs.py</pre></section>
<section id="proofs"><h2>Proofs</h2><p>The following appendices give the game, source theorem, native simulation and resource conditions for this exact implementation.</p></section>`;
const appendices=[['A','Authorization game and corollary','authorization.txt'],['B','Algebraic simulation','masking.txt'],['C','Finite source restoration','source-restoration.txt'],['D','Native adaptive simulation','simulation.txt'],['E','Protected atomic-response compiler','compiler.txt'],['F','Exact host acceptance and hash binding','hash-binding.txt'],['G','Authority primitive conditions','primitives.txt'],['H','Response-cost condition','resource-contract.txt']];
for(const [letter,title,name]of appendices){const lines=(await readFile(path.join(dir,name),'utf8')).trim().split('\n');lines.splice(0,2);const blocks=lines.join('\n').trim().split(/\n\s*\n/).map(block=>{if(/^\d+\. /.test(block)&&block.split('\n').length<3)return`<h3>${esc(block)}</h3>`;if(/^ {2,}/.test(block))return`<pre>${esc(block)}</pre>`;return`<p>${esc(block.replaceAll('\n',' ')).replace(/\b([pN2])\^(-?\d+)/g,(_,a,b)=>`${a}<sup>${b}</sup>`)}</p>`;}).join('\n');html+=`<section class="appendix"><h2>Appendix ${letter}. ${title}</h2>${blocks}</section>`;}
html+='</main></body></html>';
const dist=path.dirname(modulePath);let css=await readFile(path.join(dist,'katex.min.css'),'utf8');const fonts=[...new Set([...css.matchAll(/url\((fonts\/[^)]+)\)/g)].map(m=>m[1]))];for(const name of fonts){const ext=path.extname(name).slice(1);const mime=ext==='ttf'?'font/ttf':`font/${ext}`;const bytes=await readFile(path.join(dist,name));css=css.replaceAll(`url(${name})`,`url(data:${mime};base64,${bytes.toString('base64')})`);}
html=html.replace('<!-- KATEX_STYLE -->',`<style>${css}</style>`);
await writeFile(path.join(root,'SECURITY.html'),html);console.log(JSON.stringify({report:'SECURITY.html',appendices:appendices.length}));

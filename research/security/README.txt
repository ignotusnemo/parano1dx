Native-asset authorization security certificate
9 November 2026

SECURITY.html is the complete reading report. Its PDF is
papers/native-vault-security-report.pdf. The report includes the proof
texts and the exact resource conditions of the Category 1 corollary.

The selected profile uses 128 logical trace rows, 192 private state-mask
coordinates, committed degree 256, 4096 code positions, extension degree
eight, 64 distinct FRI positions, twenty field salts and twelve query
grinding bits. All positions are chosen by one 512-bit response.

Proofs

authorization.txt defines the public instance, fresh-request game,
complete extractor and resource corollary.
masking.txt proves full algebraic-view simulation by affine transport.
source-restoration.txt proves the finite source and query densities.
simulation.txt proves adaptive native salted-forest simulation.
compiler.txt proves the protected one-response parallel bound.
hash-binding.txt connects canonical requests and exact host acceptance.
primitives.txt records the fixed authority and generator games.
resource-contract.txt records the minimum-cost premise and units.
nist-resource-assessment.txt gives the preliminary Category 1 assessment,
its evaluated circuit model and broader cryptanalytic conditions.
quantum-circuit-resources.txt records published circuit counts and sources.
check_hash_circuits.py reproduces native fixed-prefix and output-cone
counts, including the one-bit phase implementation.

Exact reproduction

python3 research/security/poseidon_parameters.py --check
python3 research/security/check_rs_certificate.py
python3 research/security/check_profile.py
python3 research/security/check_mask_transport.py
python3 research/security/check_sampler.py
python3 research/security/check_transcript.py
python3 research/security/check_hash_circuits.py
python3 research/security/evaluate_security.py

The transcript and native hash circuit checkers require PyCryptodome.
Their references were checked with PyCryptodome 3.23.0 and Python 3.12.3.
SHA-256 uses hashlib. All dependency imports use the normal Python
module path.

check_quantum_operators.py additionally checks finite compressed-oracle
reflection and prefix invariance identities. It requires NumPy.

The selected public fixtures are in
experiments/native-vault/results/optimized-evm and
experiments/native-vault/results/optimized-solana. The Rust prover,
Solidity lifecycle harness and Solana lifecycle harness reproduce them
without RPC access or real assets. test_solana.py checks signed v1 wires
and the corresponding local instruction execution.

The quantum reference-budget ideal envelope is below 0.325524 under the
batch response-price condition c>=2^20. Its primitive-advantage margin
is 0.174476726375217. The complete classical envelope is below 0.000255
at 2^143 gates even with unit hash-call price. The JSON evaluator stores
exact fractions, upward-rounded square roots and price sensitivity.

The native counted-query theorem gives ideal proof loss below
7.762e-8 at T=2^64 physical hash calls, including constructor work.
Its independent primitive conditions are recorded in authorization.txt.

The current public-network receipts, independent RPC audits and
withdrawal links are collected in
experiments/native-vault/results/public-optimized-summary.json.
Recheck their consistency with

python3 tools/summarize_public_runs.py

The three runs cover Base Sepolia, normal Solana Devnet v1 delivery
and Solana Devnet v1 delivery with packet loss and reordering. The
audits verify all 64 positions, native request context, exact deployed
code and payout balances. Each live runner also checks nonce consumption.
Both Solana reserves are fully refunded.

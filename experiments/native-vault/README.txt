Parano1dX native-vault experiments

Public Solana Devnet v1 and Base Sepolia jobs complete deposits, proof
verification and atomic native-coin withdrawals. The vault consumes a
persistent nonce. Signed wires, public proofs and automated receipt
cross-checks record the complete jobs.

Research article:
  https://lab.parano1d.org/research/native-asset-vaults/

RESULTS.txt records measurements and their scopes. PROTOCOL.txt specifies
the construction and security conditions. TRANSPORT.txt gives exact byte
accounting and the next proof-compression research target.

Source

  auth/             Authority relation, derivation and streaming verifier.
  prover/           Randomized proof generation and strict reference checks.
  solana/           Native-SOL vault PDA and reusable public-witness window.
  evm/              Solidity verifier, vault, factory and signed tests.
  tpu-relay/        Agave QUIC delivery with explicit leader refresh.
  vendor/           Pinned backend adaptations and original licenses.
  results/          Public proofs, signed wires, fees and receipt cross-checks.

The local fixtures use a public 32-byte root and public deterministic
transaction signers. Every proof receives fresh operating-system randomness.
Public-network clients require separate private research credentials.
Wallet integration requires secret handling, an authenticated immutable
deployment manifest and the security work specified in PROTOCOL.txt.

Local reproduction

Run these commands from this directory. Tested versions are Rust 1.96,
Solana platform-tools v1.58 with Rust 1.95, Node 22, Python 3 and Solidity
0.8.30. Dependencies are pinned. Build outputs belong in target/ and .build/.

  cargo build --locked --release -p parano1dx-vault-prover
  target/release/parano1dx-vault-prover results/solana-current-local
  cp results/solana-current-local/preprocessed-cap.bin results/preprocessed-cap.bin

  cargo-build-sbf --tools-version v1.58 \
    --manifest-path solana/Cargo.toml --sbf-out-dir .build/sbf \
    -- --features wide-transport --target-dir .build/sbf-target

  python3 -m venv .build/python
  .build/python/bin/pip install -r requirements.txt
  .build/python/bin/python test_solana.py . \
    .build/sbf/parano1dx_vault_solana.so \
    target/release/parano1dx-vault-prover --v1 --chunk-bytes 3584 \
    --eager-window --fixture-directory results/solana-current-local

The harness checks signed v1 wires capped at 4,096 bytes. LiteSVM executes
the same SBF instructions through its supported compute-budget path, with
matching limits of 1,400,000 CU and a 262,144-byte heap. Public Devnet runs
exercise v1 submission and execution directly.

The transport sorts the complete multiset of 64 query indices and uses a
lossless bitmap delta. Groups of five queries give fourteen verification
windows. Each 3,584-byte upload includes a conditional completion check.
The packet completing a window verifies the whole frame atomically.
The accepted cache and query prefix survive interrupted delivery.

To replay the published local proof, add --reuse-fixture and select a
separate --output-directory. Fresh proof randomness changes delta sizes,
transaction counts and timings when generating a new fixture.

  target/release/parano1dx-vault-prover --check-stream results/solana-current-local

The native check covers all 64 queries, delta expansion, malformed inputs
and query batch sizes one through five. The SBF harness checks changed
requests, altered paths and inverses, out-of-order and duplicate uploads,
stale generations, premature payout, interrupted clients and replay.

Base local VM

  mkdir -p .build/evm
  cp evm/package.json evm/package-lock.json .build/evm/
  npm ci --prefix .build/evm --ignore-scripts

Find the Python dependency directory with:

  .build/python/bin/python -c 'import sysconfig; print(sysconfig.get_path("purelib"))'

Use that directory as PYTHON_DEPS:

  node evm/test.mjs .build/evm \
    target/release/parano1dx-vault-prover PYTHON_DEPS \
    --chain-id 8453 --result-name base

The signed local EVM run uses Base chain ID 8453 and its own authority
branch. It completes ten authorization transactions, checks runtime code
sizes and exercises authenticated-prefix recovery. The transaction gas
cap is 16,777,216 under the Prague gas schedule. The VM harnesses contact
no RPC and transfer no real assets.

Refresh the read-only Mainnet fee estimate after regenerating its fixture:

  node evm/quote-base.mjs .build/evm

The quote fixes the block, gas price, L1 data and operator charges. It uses
unsigned RLP because GasPriceOracle adds signature padding. Shared code
deployment, vault creation, rejected tests and a commercial relay-service
price are separate. The quoting client broadcasts no transactions.

Captured public Solana runs

  results/solana-devnet/spare-v1-eager-normal-1
  results/solana-devnet/spare-v1-eager-faults-1

The normal run confirms in 18.08 seconds with 88 transactions. Packet loss
and reordering confirm in 22.34 seconds with 91 transactions. Fees are
0.000445 and 0.000460 test SOL. Both return the complete temporary reserve.

  .build/python/bin/python audit_solana_devnet.py . \
    results/solana-devnet/spare-v1-eager-normal-1

Repeat for the second case. The read-only auditor checks signed wires,
all fourteen finalized verification windows, intermediate and final payout
balances, the full reserve refund, request binding and immutable ELF bytes.
independent-audit.json records an automated cross-check against a public
endpoint separate from the submitting endpoint.

The deployed ELF is results/solana-devnet/native-vault-v1.so. Its SHA-256
matches both selected receipts. deployment.json in the same directory
records its build network, program identity and source profile.

The read-only Mainnet v1 fee-layout quote is:

  .build/python/bin/python quote_v1_mainnet.py . \
    results/solana-devnet/spare-v1-eager-normal-1

It checks Mainnet v1 activation and uses fresh Mainnet blockhashes with the
observed signer layouts. It reads rent and fees without broadcasting. The
Mainnet reserve quote and isolated VM reserve record their different rent
configurations separately.

New public Devnet run

Use an owner-only wallet directory and deployment manifest matching the
wide-transport build. Build tpu-relay/ with its own pinned Cargo.lock.
The client checks the Devnet genesis hash before submission. Private roots
and fee wallets remain outside the source tree.

  .build/python/bin/python test_solana_devnet.py PYTHON_DEPS \
    target/release/parano1dx-vault-prover PRIVATE_WALLET_DIRECTORY \
    --tpu-relay TPU_RELAY_BINARY --run new-v1-case \
    --transaction-version v1 --chunks-per-transaction 1 --eager-window

Add --faults to shuffle a window batch and withhold one packet. The relayer
submits signed batches directly to validator TPU QUIC endpoints. RPC and
WebSocket supply state observations. Missing chunks are recovered from the
protected bitmap. Retries reuse signed wires until their blockhash expires.
Every run name preserves earlier receipts.

Public Base Sepolia

The captured case is results/base-sepolia/spare-public-normal-1, chain
84532. Mainnet pricing remains a separate chain-8453 record.

A private directory holds relayer.json with address, privateKey and chainId
84532, and authority-root.bin with a private 32-byte research root. Set
permissions 0700 on the directory and 0600 on both files. Fund the fee
wallet with free Base Sepolia test ETH. The client refuses other networks.

  cp results/base/compiled.json .build/evm/compiled.json
  node evm/test-base-sepolia.mjs .build/evm \
    target/release/parano1dx-vault-prover PYTHON_DEPS \
    PRIVATE_WALLET_DIRECTORY --run new-public-case

Deployment and deposit precede the authorization timer. live-result.json
records L2 receipt confirmation. finality-observation.json separately
records safe and finalized block observations.

  node evm/audit-base-sepolia.mjs .build/evm \
    results/base-sepolia/spare-public-normal-1

The second-endpoint check verifies signed transactions, canonical receipts,
code hashes, the typed request, all query positions, nonce consumption,
actual payout balances and fee reconciliation.

Reports and figures

  python3 report.py

This checks selected receipt hashes and regenerates RESULTS.txt,
fee-projection.json, latency.json and public-network-summary.json. CPU,
delivery, confirmation and finality have separate scopes. Asset-price
snapshots are time-stamped in results/market-quotes.json.

  .build/python/bin/pip install -r requirements-plots.txt
  .build/python/bin/python plot_public_results.py

Byte accounting for the selected normal public proof:

  python3 analyze_transport.py \
    results/solana-devnet/spare-v1-eager-normal-1 \
    results/transport-analysis.json

Architecture SVG and PNG exports, including the social preview, can be
regenerated from the repository root with tools/render_diagrams.py.

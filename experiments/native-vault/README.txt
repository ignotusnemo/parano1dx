Parano1dX native-vault experiments

The selected EVM and Solana v1 local jobs complete deposits, proof
verification and atomic native-coin withdrawals. The vault consumes a
persistent nonce. Signed wires, public proofs and automated receipt
cross-checks record the complete jobs.

Research article:
  https://lab.parano1d.org/research/native-asset-vaults/

RESULTS.txt records measurements and their scopes. PROTOCOL.txt specifies
the construction and security conditions. TRANSPORT.txt gives exact byte
accounting and the measured verification windows.

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
Wallet integration uses protected secret handling, an authenticated immutable
deployment manifest and the security conditions specified in PROTOCOL.txt.

Local reproduction

Run these commands from this directory. Tested versions are Rust 1.96,
Solana platform-tools v1.58 with Rust 1.95, Node 22, Python 3 and Solidity
0.8.30. Dependencies are pinned. Build outputs belong in target/ and .build/.

  python3 -m venv .build/python
  .build/python/bin/pip install -r requirements.txt
  PARANO1DX_PYTHON_DEPS="$(.build/python/bin/python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"

  cargo build --locked --release -p parano1dx-vault-prover --bin parano1dx-vault-prover
  target/release/parano1dx-vault-prover results/optimized-solana
  .build/python/bin/python evm/prepare.py results/optimized-solana --rust-parameters
  cp results/optimized-solana/preprocessed-cap.bin results/preprocessed-cap.bin
  cargo build --locked --release -p parano1dx-vault-prover --bin parano1dx-vault-prover

  cargo-build-sbf --tools-version v1.58 \
    --manifest-path solana/Cargo.toml --sbf-out-dir .build/sbf \
    -- --features wide-transport --target-dir .build/sbf-target

  .build/python/bin/python test_solana.py "$PARANO1DX_PYTHON_DEPS" \
    .build/sbf/parano1dx_vault_solana.so \
    target/release/parano1dx-vault-prover --v1 --chunk-bytes 3584 \
    --eager-window --fixture-directory results/optimized-solana

The harness checks signed v1 wires capped at 4,096 bytes. LiteSVM executes
the same SBF instructions through its supported compute-budget path, with
matching limits of 1,400,000 CU and a 262,144-byte heap. Public Devnet runs
exercise v1 submission and execution directly.

The transport sorts the complete 64-element query subset and uses a
lossless bitmap delta. Groups of six queries give twelve verification
windows. Each 3,584-byte upload includes a conditional completion check.
The packet completing a window verifies the whole frame atomically.
The accepted cache and query prefix survive interrupted delivery.

To replay the published local proof, add --reuse-fixture and select a
separate --output-directory. Fresh proof randomness changes delta sizes,
transaction counts and timings when generating a new fixture.

  target/release/parano1dx-vault-prover --check-stream results/optimized-solana

The native check covers all 64 queries, delta expansion, malformed inputs
and query batch sizes one through six. The SBF harness checks changed
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
    --chain-id 8453 --result-name optimized-evm

  node evm/check-arithmetic.mjs .build/evm results/optimized-evm

The signed local EVM run uses Base chain ID 8453 and its own authority
branch. It completes seven authorization transactions, checks runtime code
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

  results/solana-devnet/strong-v1-normal-2
  results/solana-devnet/strong-v1-faults-1

The normal run confirms in 23.01 seconds with 91 transactions. Packet loss
and reordering confirm in 25.21 seconds with 92 transactions. Fees are
0.000460 and 0.000465 test SOL. Both use twelve verification windows and
return the complete temporary reserve.

  .build/python/bin/python audit_solana_devnet.py . \
    results/solana-devnet/strong-v1-normal-2

Repeat for the second case. The read-only auditor checks signed wires,
all verification windows, intermediate and final payout
balances, the full reserve refund, request binding and immutable ELF bytes.
independent-audit.json records an automated cross-check against a public
endpoint separate from the submitting endpoint.

The deployed ELF is results/solana-devnet/optimized-native-vault-v1.so. Its SHA-256
matches both selected receipts. optimized-deployment.json in the same directory
records its build network, program identity and source profile.

The read-only Mainnet v1 fee-layout quote is:

  .build/python/bin/python quote_v1_mainnet.py . \
    results/solana-devnet/strong-v1-normal-2

It checks Mainnet v1 activation and uses fresh Mainnet blockhashes with the
observed signer layouts. It reads rent and fees without broadcasting. The
Mainnet reserve quote and isolated VM reserve record their different rent
configurations separately.

New public Devnet run

Use an owner-only wallet directory and deployment manifest matching the
wide-transport build. Build tpu-relay/ with its own pinned Cargo.lock.
The client checks the Devnet genesis hash before submission. Private roots
and fee wallets remain outside the source tree.

Build the SBF program with the network domain from the manifest:

  PARANO1DX_SOLANA_NETWORK_HEX=2660f6abec724a80f1ed8083e5aa9081ef004d9b5b8e49bd4385da4826c06646 \
    cargo-build-sbf --tools-version v1.58 --manifest-path solana/Cargo.toml \
    --sbf-out-dir .build/devnet-sbf -- --features wide-transport

Generate a public local fixture for that same network domain, then run the
complete local SBF lifecycle against this ELF. test_solana.py reads its
network from native-proof.json. Copy its successful solana-vault.json to
PROGRAM_SO.validation.json beside the ELF. deploy_solana_devnet.py checks
that receipt's network domain and ELF hash against the deployment manifest
before submitting deployment transactions.

  .build/python/bin/python deploy_solana_devnet.py PYTHON_DEPS \
    PRIVATE_WALLET_DIRECTORY PROGRAM_SO TPU_RELAY_BINARY

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

The captured case is results/base-sepolia/strong-public-normal-1, chain
84532. Mainnet pricing remains a separate chain-8453 record.

A private directory holds relayer.json with address, privateKey and chainId
84532, and authority-root.bin with a private 32-byte research root. Set
permissions 0700 on the directory and 0600 on both files. Fund the fee
wallet with free Base Sepolia test ETH. The client refuses other networks.

  node evm/test-base-sepolia.mjs .build/evm \
    target/release/parano1dx-vault-prover PYTHON_DEPS \
    PRIVATE_WALLET_DIRECTORY --run new-public-case \
    --compiled results/optimized-evm/compiled.json

Deployment and deposit precede the authorization timer. live-result.json
records L2 receipt confirmation. finality-observation.json separately
records safe and finalized block observations.

  node evm/audit-base-sepolia.mjs .build/evm \
    results/base-sepolia/strong-public-normal-1 \
    --compiled results/optimized-evm/compiled.json

The second-endpoint check verifies signed transactions, canonical receipts,
code hashes, the typed request, all query positions, nonce consumption,
actual payout balances and fee reconciliation.

Reports and figures

  python3 ../../tools/summarize_optimization.py
  python3 ../../tools/summarize_public_runs.py

The current summary records the selected local profile and verifies the
frozen publication baseline. The security report is generated by
tools/build_security_report.mjs from the repository root. CPU, delivery,
confirmation and finality have separate scopes. The 8 November publication
and its original records provide the comparison baseline.

  .build/python/bin/pip install -r requirements-plots.txt
  .build/python/bin/python plot_public_results.py

Byte accounting for the selected normal public proof:

  python3 analyze_transport.py \
    results/solana-devnet/spare-v1-eager-normal-1 \
    results/transport-analysis.json

Architecture SVG and PNG exports, including the social preview, can be
regenerated from the repository root with tools/render_diagrams.py.

# Parano1dX

Native-asset vaults on EVM networks and Solana, authorized by proofs derived from one Parano1d secret. Assets remain on their native chain. Each vault binds withdrawals to its authority commitment, request, persistent nonce and verifier parameters.

[Research article](https://lab.parano1d.org/research/native-asset-vaults/) · [Security report](SECURITY.html) ([PDF](papers/native-vault-security-report.pdf)) · [Protocol](experiments/native-vault/PROTOCOL.txt) · [Measurements](experiments/native-vault/RESULTS.txt) · [Reproduction](experiments/native-vault/README.txt)

![From one Parano1d secret to native vault addresses](assets/01-secret-to-addresses.png)

## Checked local profile

The profile uses 64 FRI queries, a 4,096-element domain and a degree-eight extension. Twenty field salts per matrix row, twelve query-grinding bits and reproducible Poseidon2 parameters strengthen the security analysis within these dimensions.

| Local check | Result |
| --- | ---: |
| Wallet proof generation, nine measured proofs | 18.75 ms median |
| Complete EVM authorization | 7 transactions, 71.16 million gas |
| Complete Solana SBF authorization | 91 transactions, 12 verification windows |
| Maximum SBF verification transaction | 1,353,196 CU |

The [optimization measurements](experiments/native-vault/results/profile-optimization/) record the profile and host measurements. Native, EVM and SBF checks include altered inputs, grinding, full query verification, nonce consumption and relayer recovery. The [security report](SECURITY.html) gives the exact reduction and primitive conditions.

## Comparison with the published research

The baseline comes from the signed local-withdrawal table in the [8 November article](https://lab.parano1d.org/research/native-asset-vaults/). The current column records the selected local profile measured on 9 November.

| Measurement | Published | Current |
| --- | ---: | ---: |
| Wallet proof generation | 53.03 / 54.39 ms | 18.75 ms median |
| EVM authorization transactions | 10 | 7 |
| Total EVM gas | 103,890,467 | 71,160,950 |
| Solana v1 authorization transactions | 87 | 91 |
| Solana ordered verification transactions | 14 | 12 |
| Maximum Solana verification CU | 1,140,062 | 1,353,196 |

EVM execution uses 31.5% less gas and three fewer transactions. Solana uses two fewer ordered verification transactions. Its complete fixture uses four more transactions and a higher peak CU charge.

The published wallet values are individual CPU samples. The current value is a nine-proof median on an Intel Core i7-1365U laptop. Both measure proof generation with preprocessing and trace construction timed separately. The [baseline record](experiments/native-vault/results/profile-optimization/published-baseline.json) identifies the publication and its original measurement files.

## Public withdrawals

The selected profile completed three public-testnet withdrawals. Separate RPC audits verified deployed code, signed transactions, every query position, request binding and payouts. Each live runner also checked nonce consumption.

| Public run | Authorization transactions | Execution charge | Confirmed withdrawal |
| --- | ---: | ---: | ---: |
| Base Sepolia | 7 | 71,251,369 gas total | 16.81 s |
| Solana Devnet v1 | 91 | 1,346,251 CU maximum | 23.01 s |
| Solana Devnet v1, packet loss and reordering | 92 | 1,364,077 CU maximum | 25.21 s |

Both Solana cases returned the full temporary reserve. Network fees were 0.000460 and 0.000465 test SOL. The timers include proof preparation and observed withdrawal confirmation. Deployment and deposits precede them. These individual network observations used a QEMU Virtual CPU version 2.5+ relayer host. The laptop benchmark is a separate measurement.

The [public-run summary](experiments/native-vault/results/public-optimized-summary.json) links withdrawal transactions, full receipts and independent audits. Reproduce its consistency checks with `python3 tools/summarize_public_runs.py`.

## Execution records

The selected profile completes both local native-asset lifecycles. Each checks canonical request binding, full proof verification, nonce consumption, relayer recovery and atomic release.

- [EVM lifecycle and gas](experiments/native-vault/results/optimized-evm/evm-vault.json)
- [Solana v1 lifecycle and compute units](experiments/native-vault/results/optimized-solana/solana-vault.json)
- [Wallet proving measurements](experiments/native-vault/results/profile-optimization/optimized-prover.json)

## Authorization

The wallet derives a separate authority branch for each network and vault index. A fresh randomized proof binds that authority to the withdrawal request. Relayers deliver the public proof and pay transaction fees. The native contract or Solana program verifies the proof before transferring funds.

The implementation uses a prime-field Poseidon2 authority relation and a hiding FRI proof with 64 queries, blowup sixteen, extension degree eight and SHA-256 || Keccak-256 commitments. Its [protocol specification](experiments/native-vault/PROTOCOL.txt) states the acceptance invariant and security conditions.

The [security report](SECURITY.html) collects the native quantum chosen-request reduction, proofs, exact calculations and NIST assessment in one document. Its appendices establish staged acceptance, source restoration, adaptive simulation and parallel fresh-request extraction in the independent-component QROM with the public capacity-seed row fixed. At a common charged budget of 2²⁴ hash calls, the combined proof and ideal-hash binding loss is below 6.423 × 10⁻³². At 2⁶⁴ calls it is below 7.762 × 10⁻⁸. The conditional Category 1 corollary uses its explicit batch response-price and authority-primitive conditions. [Reproduction](research/security/README.txt) binds the analysis to the implementation.

The [NIST-style resource assessment](research/security/nist-resource-assessment.txt) supports a conservative preliminary Category 1 classification in its documented circuit model. Its [native circuit checker](research/security/check_hash_circuits.py) costs fixed-prefix SHA-256 and Keccak-256, output projections and a one-bit phase implementation. The lowest sampled phase-data product is 3,014,449 under optimistic unit-cost XOR/AND accounting. The assessment separates these evaluated layouts from the general batch-price condition and broader cryptanalytic assumptions.

## Source and evidence

| Path | Contents |
| --- | --- |
| `experiments/native-vault/auth/` | Authority relation, derivation, transcript and streaming verifier |
| `experiments/native-vault/prover/` | Randomized proof generation and strict reference checks |
| `experiments/native-vault/evm/` | Solidity verifier, vault, factory and local/public test clients |
| `experiments/native-vault/solana/` | SBF verifier and persistent native-SOL vault |
| `experiments/native-vault/tpu-relay/` | Direct Agave QUIC delivery |
| `experiments/native-vault/results/` | Selected public v1 runs, Base run, local fixtures and fee quotes |
| `SECURITY.html` | Complete report, numerical assessment and proof appendices |
| `research/security/` | Report sources, exact calculations and reproducible checks |
| `assets/` | Architecture diagrams and measured latency figure |
| `tools/` | Figure and security-report rendering |
| `papers/` | Research article and security report PDFs |

Start with the [reproduction commands](experiments/native-vault/README.txt). Local fixtures use explicitly public research roots and deterministic transaction signers. Public-network experiments use separate private research credentials stored outside this repository. Build outputs and dependencies belong in `.build/` or `target/`.

First-party code follows the [Apache-2.0 license](LICENSE), except Solidity files with their own MIT identifiers. Vendored components retain their original licenses. [NOTICE](NOTICE) records the pinned backend and local adaptations.

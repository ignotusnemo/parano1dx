Native-vault measurement records
9 November 2026

The current local profile is recorded in optimized-evm and
optimized-solana. profile-optimization/summary.json collects its CPU,
gas and CU measurements and compares them with the published baseline.

public-optimized-summary.json collects the three current public runs:
base-sepolia/strong-public-normal-1,
solana-devnet/strong-v1-normal-2 and
solana-devnet/strong-v1-faults-1.

Each public run retains the signed transaction receipts, independent
RPC audit, request metadata and binary proof data. The Base auditor
uses the shared contracts in optimized-evm/compiled.json. The summary
records SHA-256 fingerprints of its measurement evidence.

The local evm-export.json files contain the native proof, public values
and openings used by the finite-field, transcript and mask-transport
checks. evm/prepare.py derives evm-fixture.json and stream encodings
from this export. The expanded JSON is generated when running the
EVM or Solana harness.

The published 8 November records remain in base, solana-current-local,
base-sepolia/spare-public-normal-1 and the spare-v1-eager cases under
solana-devnet. The original article and
profile-optimization/published-baseline.json identify their scope.

Check the current summaries from the repository root:

  python3 tools/summarize_optimization.py
  python3 tools/summarize_public_runs.py

research/security/ contains exact security calculations, finite
witnesses and circuit counts. SECURITY.html and its PDF present the
results and proof texts together.

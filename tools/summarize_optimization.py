#!/usr/bin/env python3
"""Collect the recorded verifier, transport and security measurements."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'experiments/native-vault/results'


def read(path):
    return json.loads(path.read_text())


def main():
    evm_path = RESULTS / 'optimized-evm/evm-vault.json'
    sol_path = RESULTS / 'optimized-solana/solana-vault.json'
    evm, sol = read(evm_path), read(sol_path)
    wallet_path = RESULTS / 'profile-optimization/optimized-prover.json'
    wallet = read(wallet_path)
    host = read(RESULTS / 'profile-optimization/host.json')
    baseline_path = RESULTS / 'profile-optimization/published-baseline.json'
    baseline = read(baseline_path)
    for name, digest in baseline['evidence_sha256'].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    old_evm = read(RESULTS / 'base/evm-vault.json')
    old_sol = read(RESULTS / 'solana-current-local/solana-vault.json')
    for name, record in [('evm', old_evm), ('solana', old_sol)]:
        assert all(record[key] == value for key, value in baseline[name].items())
    for name, record in [('base', 'base/native-proof.json'),
                         ('solana', 'solana-current-local/native-proof.json')]:
        assert round(read(RESULTS / record)['prove_ms'], 2) == baseline['wallet'][name + '_proving_ms']
    comparison_rows = [
        {'measurement': 'Wallet proof generation',
         'published': f"{baseline['wallet']['base_proving_ms']:.2f} / {baseline['wallet']['solana_proving_ms']:.2f} ms",
         'current': f"{wallet['proving_median_ms']:.2f} ms median"},
        {'measurement': 'EVM authorization transactions',
         'published': str(baseline['evm']['authorization_transactions']),
         'current': str(evm['authorization_transactions'])},
        {'measurement': 'Total EVM gas',
         'published': f"{baseline['evm']['authorization_gas']:,}",
         'current': f"{evm['authorization_gas']:,}"},
        {'measurement': 'Solana v1 authorization transactions',
         'published': str(baseline['solana']['authorization_transactions']),
         'current': str(sol['authorization_transactions'])},
        {'measurement': 'Solana ordered verification transactions',
         'published': str(baseline['solana']['verification_transactions']),
         'current': str(sol['verification_transactions'])},
        {'measurement': 'Maximum Solana verification CU',
         'published': f"{baseline['solana']['maximum_verification_transaction_CU']:,}",
         'current': f"{sol['maximum_verification_transaction_CU']:,}"},
    ]
    security_path = ROOT / 'research/security/security-evaluation.json'
    security = read(security_path)
    arithmetic_path = RESULTS / 'optimized-evm/arithmetic-checks.json'
    arithmetic = read(arithmetic_path)
    assert evm['positive_lifecycle_completed'] and sol['positive_lifecycle_completed']
    assert evm['authorization_transactions'] == 7
    assert evm['maximum_authorization_transaction_gas'] < 16777216
    assert evm['maximum_transaction_bytes'] <= 131072
    assert sol['maximum_verification_transaction_CU'] <= 1400000
    assert sol['verification_transactions'] == 12
    assert sol['proof_buffer_rent_refunded'] and arithmetic['all_checks_passed']
    repetitions = [sol] + [read(p) for p in sorted((RESULTS / 'optimized-solana').glob('repeat-*/solana-vault.json'))]
    assert all(r['positive_lifecycle_completed'] and r['replay_rejected']
               and r['maximum_verification_transaction_CU'] <= 1400000 for r in repetitions)
    result = {
        'scope': 'Recorded local CPU, EVM and SBF fixtures with signed-wire checks.',
        'profile': security['profile'],
        'host': host,
        'wallet': {'measured_proofs': wallet['measured_proofs'], 'warmup_proofs': wallet['warmup_proofs'],
                   'proving_median_ms': wallet['proving_median_ms'],
                   'scope': 'Local host, fresh randomness, common public preprocessing.'},
        'published_comparison': {
            'article': baseline['article'],
            'baseline': str(baseline_path.relative_to(ROOT)),
            'scope': 'Published local executions compared with the selected local profile.',
            'wallet_statistics': 'Published individual CPU samples and current nine-proof median on an Intel Core i7-1365U laptop. Preprocessing and trace construction are separate.',
            'rows': comparison_rows,
            'evm_gas_reduction_percent': 100 * (1 - evm['authorization_gas'] / baseline['evm']['authorization_gas']),
            'solana_authorization_transaction_change': sol['authorization_transactions'] - baseline['solana']['authorization_transactions'],
            'solana_verification_transaction_change': sol['verification_transactions'] - baseline['solana']['verification_transactions']},
        'evm': {k: evm[k] for k in ['authorization_transactions', 'authorization_gas',
            'maximum_authorization_transaction_gas', 'maximum_transaction_bytes', 'verifier_code_bytes']},
        'solana': {k: sol[k] for k in ['authorization_transactions', 'verification_transactions',
            'maximum_verification_transaction_CU', 'delta_payload_bytes', 'proof_buffer_space_bytes',
            'proof_buffer_rent_refunded']},
        'solana_repetitions': {'cases': len(repetitions),
            'transaction_counts': [r['authorization_transactions'] for r in repetitions],
            'maximum_CU': max(r['maximum_verification_transaction_CU'] for r in repetitions),
            'all_lifecycles_and_replay_checks_passed': True},
        'security': {
            'source_query_error_bits': security['public_coin_ledger']['query_error']['negative_log2'],
            'native_grinding_query_density_bits': security['native_grinding_ledger']['query_group_density']['negative_log2'],
            'combined_loss_at_T_2_24': security['native_quantum_authorization']['at_query_budget_bits']['24']['combined'],
            'conditions': security['native_quantum_authorization']['primitive_conditions'],
            'nist_category': security['nist']['category'],'nist_status':security['nist']['status'],'ideal_Category_1_bound':security['nist']['maximum_ideal_bound'],'resource_condition':security['nist']['resource_condition']},
        'arithmetic': arithmetic,
        'evidence_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [evm_path, sol_path, wallet_path, arithmetic_path, security_path, baseline_path]}}
    out = RESULTS / 'profile-optimization/summary.json'
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ['wallet', 'evm', 'solana_repetitions']}))


if __name__ == '__main__':
    main()

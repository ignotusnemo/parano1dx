#!/usr/bin/env python3
"""Check the selected public-network receipts and collect their measurements."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'experiments/native-vault/results'


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    evidence = []
    base_dir = RESULTS / 'base-sepolia/strong-public-normal-1'
    base_path = base_dir / 'live-result.json'
    base, base_audit = read(base_path), read(base_dir / 'independent-audit.json')
    assert base['chain_id'] == base_audit['chain_id'] == 84532
    assert base_audit['source_receipt_sha256'] == digest(base_path)
    assert base['positive_lifecycle_completed'] and base['replay_rejected']
    assert base['native_transcript_matches'] and base['payer_balance_reconciled']
    assert base['real_assets_used'] is False
    for key in ['canonical_receipts_verified', 'code_hashes_verified',
                'all_64_queries_present', 'typed_request_verified',
                'native_request_context_verified', 'payout_balances_verified',
                'nonce_consumed_once', 'fees_reconciled']:
        assert base_audit[key], key
    authorizations = [r for r in base['records'] if r['scope'] == 'authorization']
    assert len(authorizations) == base['authorization_transactions'] == 7
    assert sum(r['gas_used'] for r in authorizations) == base['authorization_gas']
    assert max(r['gas_used'] for r in authorizations) == base['maximum_authorization_transaction_gas']
    assert all(r['receipt']['status'] == '0x1' for r in authorizations)
    assert base['maximum_authorization_transaction_gas'] < 16777216
    assert base['withdrawal_hash'] == base_audit['withdrawal_hash']
    compiled_path = RESULTS / 'optimized-evm/compiled.json'
    evidence.extend([base_path, base_dir / 'independent-audit.json',
                     compiled_path, base_dir / 'native-proof.json'])
    base_summary = {k: base[k] for k in [
        'chain_id', 'authorization_transactions', 'authorization_gas',
        'maximum_authorization_transaction_gas', 'confirmed_s',
        'wallet_proving_ms', 'authorization_fee_wei', 'execution_fee_wei',
        'l1_data_fee_wei', 'operator_fee_wei', 'withdrawal_hash',
        'withdrawal_explorer_url', 'timing_scope', 'fee_scope']}
    base_summary['record'] = str(base_path.relative_to(ROOT))
    base_summary['independent_audit'] = str((base_dir / 'independent-audit.json').relative_to(ROOT))
    base_summary['compiled_contracts_record'] = str(compiled_path.relative_to(ROOT))

    deployment_path = RESULTS / 'solana-devnet/optimized-deployment.json'
    validation_path = RESULTS / 'solana-devnet/optimized-build-validation.json'
    elf_path = RESULTS / 'solana-devnet/optimized-native-vault-v1.so'
    deployment, validation = read(deployment_path), read(validation_path)
    elf_hash = digest(elf_path)
    assert elf_hash == deployment['elf_sha256'] == validation['program_elf_sha256']
    assert deployment['immutable_verified'] and validation['positive_lifecycle_completed']
    assert deployment['real_assets_used'] is False
    assert validation['maximum_verification_transaction_CU'] <= 1400000
    evidence.extend([deployment_path, validation_path, elf_path,
                     RESULTS / 'solana-devnet/optimized-build-manifest.json'])
    solana = []
    for case, faulted in [('strong-v1-normal-2', False), ('strong-v1-faults-1', True)]:
        case_dir = RESULTS / 'solana-devnet' / case
        receipt_path = case_dir / 'live-result.json'
        audit_path = case_dir / 'independent-audit.json'
        receipt, audit = read(receipt_path), read(audit_path)
        assert audit['live_receipt_sha256'] == digest(receipt_path)
        assert receipt['program_id'] == deployment['program_id']
        assert receipt['elf_sha256'] == elf_hash
        assert receipt['genesis_hash'] == audit['genesis_hash'] == deployment['genesis_hash']
        assert receipt['transaction_version'] == 'v1'
        assert receipt['query_batch_size'] == 6
        assert receipt['ordered_verification_windows'] == len(receipt['verification_receipts']) == 12
        assert receipt['reserve_refunded'] and receipt['payout_and_nonce_checked']
        assert receipt['fault_injection_enabled'] is faulted
        assert receipt['real_assets_used'] is False
        for key in ['signed_wires_valid', 'all_verification_windows_finalized',
                    'all_64_query_positions_present', 'payout_lamport_deltas_verified',
                    'complete_reserve_refund_verified', 'all_captured_transactions_finalized',
                    'intermediate_payouts_absent', 'immutable_program_ELF_verified',
                    'proof_request_matches', 'request_binding_verified',
                    'signature_fees_match_balance_deltas', 'native_request_context_verified']:
            assert audit[key], (case, key)
        maximum_cu = max(r['compute_units'] for r in receipt['verification_receipts'])
        assert maximum_cu == audit['maximum_verification_CU'] <= 1400000
        auth_signatures = {r['signature'] for r in receipt['transactions'] if r['scope'] == 'authorization'}
        assert len(auth_signatures) == receipt['unique_authorization_transactions']
        assert receipt['withdrawal_signature'] in auth_signatures
        assert receipt['rebroadcast_submissions'] == 0
        fault_cases = {e['case'] for e in receipt['fault_events']}
        if faulted:
            assert {'reordered_window_batch_with_lost_packet',
                    'bitmap_resume_missing_chunks_only'} <= fault_cases
        else:
            assert not fault_cases
        native_path = case_dir / 'native-proof.json'
        native = read(native_path)
        row = {k: receipt[k] for k in [
            'program_id', 'transaction_version', 'unique_authorization_transactions',
            'ordered_verification_windows', 'withdrawal_confirmed_s',
            'withdrawal_finalized_s', 'actual_network_fee_lamports',
            'temporary_reserve_lamports', 'reserve_refunded',
            'withdrawal_signature', 'fault_injection_enabled', 'scope']}
        row.update({
            'case': case, 'maximum_verification_CU': maximum_cu,
            'wallet_proving_ms': native['prove_ms'],
            'record': str(receipt_path.relative_to(ROOT)),
            'independent_audit': str(audit_path.relative_to(ROOT)),
            'fault_events': receipt['fault_events'],
            'withdrawal_explorer_url': 'https://explorer.solana.com/tx/'
                + receipt['withdrawal_signature'] + '?cluster=devnet'})
        solana.append(row)
        evidence.extend([receipt_path, audit_path, native_path, case_dir / 'transaction-journal.jsonl'])

    security = read(ROOT / 'research/security/security-evaluation.json')
    result = {
        'date': '2026-11-09', 'profile': security['profile'], 'real_assets_used': False,
        'host': 'QEMU Virtual CPU version 2.5+',
        'measurement_scope': 'Individual public-testnet observations from a common research relayer host. '
            'Timers include proof preparation and observed withdrawal confirmation. '
            'Deployment and vault deposits precede the timers. Testnet fees are recorded in native units.',
        'base_sepolia': base_summary, 'solana_devnet': solana,
        'independent_audits_passed': True,
        'evidence_sha256': {str(p.relative_to(ROOT)): digest(p) for p in evidence}}
    out = RESULTS / 'public-optimized-summary.json'
    out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'public_cases': 3, 'independent_audits_passed': True,
                      'base_gas': base['authorization_gas'],
                      'solana_maximum_CU': max(r['maximum_verification_CU'] for r in solana),
                      'all_temporary_reserves_refunded': True}))


if __name__ == '__main__':
    main()

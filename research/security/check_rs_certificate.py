#!/usr/bin/env python3
"""Verify finite first-order Reed–Solomon certificates for the fixed profile."""
from fractions import Fraction as F
from pathlib import Path
from math import comb, log2
import argparse
import hashlib
import json

HERE = Path(__file__).resolve().parent
P = 2130706433


def ceil(value):
    return -(-value.numerator // value.denominator)


def support(n, k, agreement, multiplicity, derivative, degree, height):
    """DKT26 Proposition C.2, derivative-weighted support, and Lemma 5.5."""
    assert 2 <= k < agreement <= n
    assert multiplicity >= 1 and 0 <= derivative <= degree
    assert P > max(k - 1, derivative)
    d = k - 1
    coefficients = rows = 0
    for t in range(degree + 1):
        cap = min(t, derivative)
        base = multiplicity * agreement - d * t
        lo = max(0, 1 - base)
        if lo <= cap:
            coefficients += ((cap - lo + 1) * base
                             + (cap + lo) * (cap - lo + 1) // 2)
        for s in range(max(0, t - derivative), multiplicity):
            if s + (d - 1) * t < multiplicity * agreement:
                rows += max(0, min(multiplicity - s,
                                  min(t, s) - max(0, t - derivative) + 1))
    constraints = n * rows
    assert coefficients > constraints
    # A polynomial kernel vector of degree H exists by a scalar coefficient
    # count. Dividing its content makes every specialization nonzero.
    left = coefficients * (height + 1)
    right = constraints * (height + degree + 1)
    assert left > right
    curve_margin = (coefficients - constraints) * height - constraints * degree
    assert curve_margin > 0
    lam = F(n - d, agreement - d)
    b = degree * (2 * derivative + 1)
    h = height * (2 * derivative + 1)
    ordinary = ((2 * b - 1) * h + lam * (h + b + 4 * d * b * h)
                + (n - d - 1) * b)
    regular = ((48 * d * d * height + 16 * d) * lam**2 * degree * derivative
               + 8 * d * (n - d - 1) * lam * degree * derivative)
    list_bound = ceil(4 * d * lam * degree * derivative
                      + 2 * degree * derivative + degree)
    return {
        'domain': n, 'dimension': k, 'agreement_count': agreement,
        'multiplicity': multiplicity, 'derivative_degree': derivative,
        'total_jet_degree': degree, 'line_challenge_degree': height,
        'source_coefficients': str(coefficients), 'local_rank_upper': rows,
        'global_rank_upper': str(constraints),
        'kernel_dimension_margin': str(left - right),
        'curve_kernel_margin_per_degree': str(curve_margin),
        'characteristic_lower_bound': max(d, derivative),
        'decoder_characteristic_lower_bound': 2 * (degree + 1)**3,
        'list_bound_upper': list_bound,
        'line_exception_count_upper': str(ceil(ordinary + regular)),
        'curve_rule': 'degree ell has exception count at most ell times this line envelope',
    }


def orbit_identities():
    """Compare the native fold formula with the Fourier coefficient map."""
    cases = 0
    for arity in [2, 4]:
        omega = pow(3, (P - 1) // arity, P)
        assert pow(omega, arity, P) == 1
        assert pow(omega, arity // 2, P) != 1
        for position in [0, 1, 7, 63, 1023]:
            x = 3 * pow(3, ((P - 1) // 4096) * position, P) % P
            for basis in range(arity):
                values = [int(j == basis) for j in range(arity)]
                fourier = [sum(values[j] * pow(omega, (-j * i) % arity, P)
                               for j in range(arity)) * pow(arity, -1, P)
                           * pow(x, -i, P) % P for i in range(arity)]
                if arity == 2:
                    native = [(values[0] + values[1]) * pow(2, -1, P) % P,
                              (values[0] - values[1]) * pow(2 * x, -1, P) % P]
                else:
                    r0, r1, r2, r3 = [values[i] for i in [0, 2, 1, 3]]
                    a0, a1 = r0 + r1, r0 - r1
                    a2, a3 = r2 + r3, (r2 - r3) * -omega
                    native = [c * pow(4, -1, P) * pow(x, -i, P) % P
                              for i, c in enumerate([a0 + a2, a1 + a3,
                                                     a0 - a2, a1 - a3])]
                assert native == fourier
                cases += 1
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=HERE / 'rs-certificate.json')
    args = parser.parse_args()
    # Finite witnesses to the support inequalities. These are analysis
    # parameters. The authorization implementation stays at its fixed profile.
    source = support(4096,257,896,256,157,888,405516956)
    gamma = support(4096,256,896,192,126,672,177710)
    folding = [(4,gamma),(4,support(1024,64,224,64,42,227,53572)),
               (4,support(256,16,56,24,15,87,2838)),(4,support(64,4,14,4,2,18,390))]
    for entry in [source] + [entry for _, entry in folding]:
        assert P > 2 * (entry['total_jet_degree'] + 1)**3
    agreement = F(source['agreement_count'], source['domain'])
    for arity, entry in folding:
        assert entry['agreement_count'] == ceil(agreement * entry['domain'])
        assert entry['dimension'] % arity == 0
    cap = source['list_bound_upper']
    assert cap**2 >= 8192
    composition = 62 * cap
    outer = 4609 * cap**2
    batching = 267 * int(gamma['line_exception_count_upper'])
    fold = sum((arity - 1) * int(entry['line_exception_count_upper'])
               for arity, entry in folding)
    numerator = composition + outer + batching + fold
    query_error = F(comb(source['agreement_count'], 64), comb(4096, 64))
    error = query_error + F(numerator, P**8)
    result = {
        'scope': 'public-coin source restoration at the fixed implementation parameters',
        'reference': 'https://eprint.iacr.org/2026/2056',
        'reference_revision': '2 November 2026',
        'reference_artifact': 'https://github.com/quangvdao/rs-beyond-johnson/tree/fd6d84edd50dcca7c0b3f388e0b4824d9daa082d',
        'theorems': ['Proposition C.2', 'Lemma 5.5', 'Remark 6.1',
                     'Corollaries 6.4 and 6.6'],
        'base_prime': P, 'extension_degree': 8, 'codeword_rows': 4096,
        'queries': 64, 'agreement_upper': str(agreement),
        'query_sampling': 'uniform 64-element subset without replacement',
        'query_error_bits': log2(query_error.denominator) - log2(query_error.numerator),
        'source': source, 'gamma': gamma,
        'folds': [{'arity': arity, 'certificate': entry} for arity, entry in folding],
        'composition_charge': str(composition), 'outer_charge': str(outer),
        'batching_charge': str(batching), 'fold_charge': str(fold),
        'field_error_numerator': str(numerator),
        'field_error_denominator': str(P**8),
        'combined_error_bits': log2(error.denominator) - log2(error.numerator),
        'native_fold_matrix_cases': orbit_identities(),
        'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'certificates_checked': 1+len(folding), 'queries': 64,
                      'codeword_rows': 4096, 'extension_degree': 8,
                      'source_error_bits': result['combined_error_bits'],
                      'native_fold_matrix_cases': result['native_fold_matrix_cases']}))


if __name__ == '__main__':
    main()

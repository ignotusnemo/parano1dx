#!/usr/bin/env python3
"""Finite matrix checks of the native compiler's compressed-oracle identities."""
from fractions import Fraction
from itertools import combinations, product
from math import sqrt
from pathlib import Path
import json

import numpy as np


def reflection(output_size, allowed=None):
    allowed = list(range(output_size)) if allowed is None else list(allowed)
    result = np.eye(output_size+1)
    if not allowed:
        return result
    difference = np.zeros(output_size+1)
    difference[-1] = 1
    difference[allowed] = -1/sqrt(len(allowed))
    return result-np.outer(difference, difference)


def cold_read_errors():
    errors = []
    for n in [2, 4, 8]:
        c = np.kron(reflection(n), np.eye(n))
        lookup = np.zeros_like(c)
        for row, answer in product(range(n+1), range(n)):
            output = answer ^ (row if row < n else 0)
            lookup[row*n+output, row*n+answer] = 1
        initial = np.zeros((n+1)*n)
        initial[n*n] = 1
        ideal = np.zeros_like(initial)
        for y in range(n):
            ideal[y*n+y] = 1/sqrt(n)
        actual = c@lookup@c@initial
        error = np.linalg.norm(actual-ideal)
        assert abs(error-sqrt(2/n)) < 1e-12
        for count in range(n):
            allowed = range(count, n)
            altered = np.kron(reflection(n, allowed), np.eye(n))
            protected = altered@lookup@altered
            assert np.linalg.norm(c@lookup@c-protected, ord=2) <= 4*sqrt(count/n)+1e-12
        errors.append(abs(error-sqrt(2/n)))
    return max(errors)


def ordinary_query_pair():
    n, rows = 2, 2
    databases = list(product(range(n+1), repeat=rows))
    index = {d: i for i, d in enumerate(databases)}
    c_db = np.kron(reflection(n), reflection(n))
    c = np.kron(c_db, np.eye(16))
    lookups = [np.zeros((144, 144)) for _ in range(2)]
    for d_index, d in enumerate(databases):
        for a, b in product(range(4), repeat=2):
            current = d_index*16+a*4+b
            a_input, a_answer = divmod(a, 2)
            b_input, b_answer = divmod(b, 2)
            a_value = d[a_input] if d[a_input] < n else 0
            b_value = d[b_input] if d[b_input] < n else 0
            lookups[0][d_index*16+(2*a_input+(a_answer ^ a_value))*4+b, current] = 1
            lookups[1][d_index*16+a*4+2*b_input+(b_answer ^ b_value), current] = 1
    first, second = [c@lookup@c for lookup in lookups]
    commutator = np.max(np.abs(first@second-second@first))
    assert commutator < 1e-12

    c_one = np.kron(c_db, np.eye(4))
    lookup = np.zeros((36, 36))
    row_swap = np.zeros((36, 36))
    input_swap = np.kron(np.eye(9), np.kron(np.array([[0, 1], [1, 0]]), np.eye(2)))
    for d_index, d in enumerate(databases):
        for query, answer in product(range(2), repeat=2):
            current = d_index*4+query*2+answer
            value = d[query] if d[query] < n else 0
            lookup[d_index*4+query*2+(answer ^ value), current] = 1
            row_swap[index[tuple(reversed(d))]*4+query*2+answer, current] = 1
    oracle = c_one@lookup@c_one
    covariance = np.max(np.abs(row_swap@oracle@row_swap-input_swap@oracle@input_swap))
    assert covariance < 1e-12
    return oracle, row_swap, commutator, covariance


def row_decomposition(oracle, row_swap):
    rng = np.random.default_rng(20261108)
    residuals = []
    for query_count in [1, 2, 3, 5]:
        gates = []
        for _ in range(query_count+1):
            samples = rng.normal(size=(4, 4))+1j*rng.normal(size=(4, 4))
            unitary, _ = np.linalg.qr(samples)
            gates.append(np.kron(np.eye(9), unitary))
        state = np.zeros(36, dtype=complex)
        state[8*4] = 1
        state = gates[0]@state
        before = []
        for i in range(query_count):
            before.append(state)
            state = gates[i+1]@oracle@state
        terms = []
        for i in range(query_count):
            suffix = gates[i+1]
            for j in range(i+1, query_count):
                suffix = gates[j+1]@oracle@suffix
            for h in [0, 1]:
                local = np.zeros((2, 2))
                local[1-h, h] = 1/sqrt(2)
                local[h, h] = -1/sqrt(2)
                kraus = np.kron(np.eye(9), np.kron(local, np.eye(2)))
                terms.append(-suffix@oracle@row_swap@kraus@before[i])
                terms.append(suffix@row_swap@kraus@oracle@before[i])
        residual = np.linalg.norm(state-row_swap@state-sqrt(2)*sum(terms))
        assert residual < 1e-12
        contraction = np.array([int((i//4)//3 == 1) for i in range(36)])
        lhs = np.linalg.norm(contraction*state)**2
        rhs = (8*query_count+1)*(np.linalg.norm(contraction*(row_swap@state))**2
                                +sum(np.linalg.norm(contraction*x)**2 for x in terms))
        assert lhs <= rhs+1e-12
        residuals.append(residual)
    return max(residuals)


def protected_prefix():
    n = 4
    databases = list(product(range(n+1), repeat=2))
    index = {d: i for i, d in enumerate(databases)}
    root = 3
    labels = [sum(1 << i for i, x in enumerate(d) if x == root) for d in databases]
    residual = 0.0
    for query in range(2):
        compression = np.zeros((25, 25))
        for column, d in enumerate(databases):
            other = 1-query
            forbidden = {query, root}
            if d[other] < n:
                forbidden.update([other, d[other]])
            local = reflection(n, [y for y in range(n) if y not in forbidden])
            for y in range(n+1):
                output = list(d)
                output[query] = y
                compression[index[tuple(output)], column] = local[y, d[query]]
        assert np.max(np.abs(compression@compression-np.eye(25))) < 1e-12
        c = np.kron(compression, np.eye(n))
        lookup = np.zeros((100, 100))
        for row, d in enumerate(databases):
            for answer in range(n):
                value = d[query] if d[query] < n else 0
                lookup[row*n+(answer ^ value), row*n+answer] = 1
        protected = c@lookup@c
        for label in range(4):
            projector = np.diag(np.repeat([int(x == label) for x in labels], n))
            residual = max(residual, np.max(np.abs(projector@protected-protected@projector)))
    assert residual < 1e-12
    return residual


def cold_group_counts():
    n, initial_input = 4, 0
    databases = [dict()]
    databases.extend([{x: y} for x in range(1, n) for y in range(n)])
    groups = 0
    for length in [1, 2, 3]:
        images = set()
        counts = []
        for d in databases:
            accepted = []
            for values in product(range(n), repeat=length):
                current, word, cold = initial_input, dict(d), True
                for value in values:
                    if current in word:
                        cold = False
                        break
                    word[current] = value
                    current = value
                if cold:
                    image = (values, tuple(sorted(word.items())))
                    assert image not in images
                    images.add(image)
                    accepted.append(values)
            counts.append(accepted)
        for size in range(n+1):
            for subset in combinations(range(n), size):
                good = set(subset)
                density = Fraction(size, n)**length
                for paths in counts:
                    probability = Fraction(sum(all(y in good for y in path) for path in paths), n**length)
                    assert probability <= density
                groups += 1
    return groups


def main():
    cold = cold_read_errors()
    oracle, row_swap, commutator, covariance = ordinary_query_pair()
    decomposition = row_decomposition(oracle, row_swap)
    protected = protected_prefix()
    groups = cold_group_counts()
    result = {
        'scope': 'finite matrix identities and exact small-domain cold-group counts',
        'numpy_version': np.__version__,
        'ordinary_query_commutator_max_entry': float(commutator),
        'row_relabel_covariance_max_entry': float(covariance),
        'row_decomposition_max_state_residual': float(decomposition),
        'cold_read_norm_formula_max_error': float(cold),
        'protected_root_projector_commutator_max_entry': float(protected),
        'cold_group_predicate_cases': groups,
        'cold_group_reconstruction_injective': True,
        'threshold': 1e-12,
        'all_checks_passed': True,
    }
    Path(__file__).with_name('quantum-operator-checks.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

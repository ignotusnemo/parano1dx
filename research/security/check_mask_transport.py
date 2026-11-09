#!/usr/bin/env python3
"""Exact production-size polynomial checks for the mask-transport argument."""
from pathlib import Path
from random import Random
import argparse
import json
import re

from check_profile import P, ROOT, power as extension_power, rank


def trim(a):
    a = [x % P for x in a]
    while len(a) > 1 and not a[-1]:
        a.pop()
    return a


def add(a, b):
    c = [0] * max(len(a), len(b))
    for i, x in enumerate(a):
        c[i] += x
    for i, x in enumerate(b):
        c[i] += x
    return trim(c)


def scale(a, c):
    return trim([x * c % P for x in a])


def sub(a, b):
    return add(a, scale(b, -1))


def mul(a, b):
    c = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if y:
                    c[i + j] += x * y
    return trim(c)


def divide(a, b):
    a, b = trim(a), trim(b)
    c = [0] * max(1, len(a) - len(b) + 1)
    inv = pow(b[-1], -1, P)
    while a != [0] and len(a) >= len(b):
        at, value = len(a) - len(b), a[-1] * inv % P
        c[at] = value
        for i, x in enumerate(b):
            a[at + i] = (a[at + i] - value * x) % P
        a = trim(a)
    return trim(c), a


def mod(a, b):
    return divide(a, b)[1]


def inverse(a, modulus):
    old, current, u, v = modulus, mod(a, modulus), [0], [1]
    while current != [0]:
        q, rem = divide(old, current)
        old, current, u, v = current, rem, v, sub(u, mul(q, v))
    assert len(old) == 1 and old[0]
    return mod(scale(u, pow(old[0], -1, P)), modulus)


def product(items):
    out = [1]
    for a in items:
        out = mul(out, a)
    return out


def evaluate(a, x):
    out = 0
    for c in reversed(a):
        out = (out * x + c) % P
    return out


def crt(residues, factors):
    modulus = product(factors)
    out = [0]
    for value, factor in zip(residues, factors, strict=True):
        cofactor, rem = divide(modulus, factor)
        assert rem == [0]
        out = add(out, mul(cofactor, mod(mul(value, inverse(cofactor, factor)), factor)))
    return mod(out, modulus)


def ext(value):
    if isinstance(value, int):
        return (value % P,) + (0,) * 7
    return tuple(value) + (0,) * (8 - len(value))


ZERO, ONE = ext(0), ext(1)


def eadd(a, b):
    return tuple((x + y) % P for x, y in zip(a, b))


def eneg(a):
    return tuple(-x % P for x in a)


def emul(a, b):
    c = [0] * 15
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if y:
                    c[i + j] += x * y
    for i in range(14, 7, -1):
        c[i - 8] += 3 * c[i]
    return tuple(x % P for x in c[:8])


def etrim(a):
    while len(a) > 1 and a[-1] == ZERO:
        a.pop()
    return a


def epadd(a, b):
    c = [ZERO] * max(len(a), len(b))
    for i, x in enumerate(a):
        c[i] = eadd(c[i], x)
    for i, x in enumerate(b):
        c[i] = eadd(c[i], x)
    return etrim(c)


def epdivide_monic(a, b):
    a = a[:]
    assert b[-1] == ONE
    c = [ZERO] * max(1, len(a) - len(b) + 1)
    while a != [ZERO] and len(a) >= len(b):
        at, value = len(a) - len(b), a[-1]
        c[at] = value
        for i, x in enumerate(b):
            a[at + i] = eadd(a[at + i], eneg(emul(value, x)))
        a = etrim(a)
    return etrim(c), a


def field_basis_coordinates(value, basis):
    matrix = [[basis[j][i] for j in range(8)] + [value[i]] for i in range(8)]
    for j in range(8):
        pivot = next(i for i in range(j, 8) if matrix[i][j])
        matrix[j], matrix[pivot] = matrix[pivot], matrix[j]
        inv = pow(matrix[j][j], -1, P)
        matrix[j] = [x * inv % P for x in matrix[j]]
        for i in range(8):
            if i != j:
                c = matrix[i][j]
                matrix[i] = [(x - c*y) % P for x, y in zip(matrix[i], matrix[j])]
    return [row[8] for row in matrix]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('mask-transport-check.json'))
    args = parser.parse_args()
    rng = Random('Parano1dX public mask-transport arithmetic vector')
    polynomial = lambda n: [rng.randrange(P) for _ in range(n)]
    data = json.loads((ROOT/'experiments/native-vault/results/optimized-solana/evm-export.json').read_text())
    ri=pow(2**32,-1,P)
    generators=[x*ri%P for x in data['generators_raw']]
    values=lambda name: [x*ri%P for x in data['quotient_shifts_raw']]
    g, g12 = generators[6], generators[12]
    queries=[];used=set()
    candidates=values("QUOTIENT_SHIFTS")+[3*pow(g12,i,P)%P for i in range(4096)]
    for q in candidates:
        if q not in used and g*q%P not in used:
            queries.append(q);used.update([q,g*q%P])
        if len(queries)==64:break
    rotated = [g*q % P for q in queries]
    assert len(set(queries + rotated)) == 128
    z, gz = ext([0, 1]), ext([0, g])
    mz, mgz = [-3] + [0]*7 + [1], [-3*pow(g, 8, P)] + [0]*7 + [1]
    factors = [[-q, 1] for q in queries] + [mz]
    observed = product(factors)
    main_observed = product([[-q, 1] for q in queries + rotated] + [mz, mgz])
    assert len(observed)-1 == 72 and len(main_observed)-1 == 144
    zh = [-1] + [0]*127 + [1]
    execution = [1] + [0]*63 + [1]
    selector=scale([1]+[0]*63+[-1]+[0]*63+[1]+[0]*63+[-1],pow(4,-1,P))
    assert mul(selector,execution)==scale([-1]+[0]*255+[1],-pow(4,-1,P))
    zh_inverse = inverse(execution, main_observed)

    def couple(a, b):
        r = polynomial(192)
        adjustment = mod(mul(sub(a, b), zh_inverse), main_observed)
        left, right = add(a, mul(execution, r)), add(b, mul(execution, add(r, adjustment)))
        assert mod(sub(left, right), main_observed) == [0]
        assert len(left) <= 256 and len(right) <= 256
        return left, right

    a, b = polynomial(64), polynomial(64)
    a1, a2 = couple(a, b)
    b1, b2 = couple(mod(mul(mul(a, a), a), execution), mod(mul(mul(b, b), b), execution))

    def quotient(x, y):
        c = mul(sub(mul(mul(x, x), x), y), selector)
        out, rem = divide(c, zh)
        assert rem == [0] and len(out) <= 1024
        return out

    q1, q2 = quotient(a1, b1), quotient(a2, b2)
    assert mod(sub(q2, q1), observed) == [0]
    shifts = values('QUOTIENT_SHIFTS')
    vanish = [[-pow(s, 128, P)] + [0]*127 + [1] for s in shifts]
    constants = [pow(evaluate(product([v for j, v in enumerate(vanish) if i != j]), shifts[i]), -1, P)
                 for i in range(8)]
    weights = [scale(product([v for j, v in enumerate(vanish) if i != j]), constants[i]) for i in range(8)]
    left, right = [mod(q1, v) for v in vanish], [mod(q2, v) for v in vanish]
    residues, zero_cases = [[] for _ in range(7)], set()
    ratios = [c*pow(constants[7], -1, P) % P for c in constants[:7]]
    for factor in factors:
        vi = [mod(v, factor) for v in vanish]
        delta = [mod(sub(y, x), factor) for x, y in zip(left, right)]
        absent = [i for i, v in enumerate(vi) if v == [0]]
        assert len(absent) <= 1
        zero_cases.add(absent[0] if absent else None)
        t = [mod(mul(scale(delta[i], -1), inverse(vi[i], factor)), factor) if vi[i] != [0] else [0]
             for i in range(7)]
        if absent and absent[0] < 7:
            k = absent[0]
            target = mod(mul(delta[7], inverse(vi[7], factor)), factor)
            for i in range(7):
                if i != k:
                    target = sub(target, scale(t[i], ratios[i]))
            t[k] = mod(scale(target, pow(ratios[k], -1, P)), factor)
        for i in range(7):
            residues[i].append(t[i])
    assert zero_cases == set(range(8)) | {None}
    translations = [crt(r, factors) for r in residues]
    translations.append(scale(sum_polynomials([scale(t, c) for t, c in zip(translations, ratios)]), -1))
    masks = [polynomial(128) for _ in range(7)]
    masks.append(scale(sum_polynomials([scale(t, c) for t, c in zip(masks, ratios)]), -1))
    left = [add(q, mul(v, t)) for q, v, t in zip(left, vanish, masks)]
    right = [add(q, mul(v, add(t, dt))) for q, v, t, dt in zip(right, vanish, masks, translations)]
    assert all(mod(sub(x, y), observed) == [0] for x, y in zip(left, right))
    assert sum_polynomials([mul(w, q) for w, q in zip(weights, left)]) == q1
    assert sum_polynomials([mul(w, q) for w, q in zip(weights, right)]) == q2

    gamma = ext([2, 1])
    basis = [ONE]
    for _ in range(7):
        basis.append(emul(basis[-1], gamma))
    assert rank(list(map(list, zip(*basis)))) == 8
    all_powers = basis[:]
    for _ in range(8):
        all_powers.append(emul(all_powers[-1], gamma))
    kernel = []
    for i in range(8):
        vector = [-c % P for c in field_basis_coordinates(all_powers[8+i], basis)]
        vector += [int(i == j) for j in range(8)]
        image = ZERO
        for c, power in zip(vector, all_powers):
            image = eadd(image, emul(ext(c), power))
        assert image == ZERO
        kernel.append(vector)
    assert rank(kernel) == 8

    def deep_difference(delta, point, coefficient):
        result, rem = epdivide_monic([emul(ext(v), coefficient) for v in delta], [eneg(point), ONE])
        assert rem == [ZERO]
        return result

    difference = deep_difference(sub(a2, a1), z, ONE)
    difference = epadd(difference, deep_difference(sub(a2, a1), gz, gamma))
    for i in range(8):
        difference = epadd(difference, deep_difference(sub(right[i], left[i]), z, basis[i]))
    zq = product([[-q, 1] for q in queries])
    ae, rem = epdivide_monic([ext(x) for x in mul(zq, mz)], [eneg(z), ONE])
    assert rem == [ZERO]
    residual, rem = epdivide_monic(difference, ae)
    assert rem == [ZERO] and len(residual) <= 184
    parts = list(map(list, zip(*(field_basis_coordinates(eneg(v), basis) for v in residual))))
    randomizer = [mul(mul(zq, mz), part) for part in parts]
    assert all(len(r) <= 256 and mod(r, mul(zq, mz)) == [0] for r in randomizer)
    correction = [ZERO]
    for i, r in enumerate(randomizer):
        correction = epadd(correction, deep_difference(r, z, basis[i]))
    assert epadd(difference, correction) == [ZERO]
    subfield = ext([0, 0, 1])
    assert ext(extension_power([0, 0, 1], P**4)) == subfield
    powers = [ONE]
    for _ in range(7):
        powers.append(emul(powers[-1], subfield))
    subfield_rank = rank(list(map(list, zip(*powers))))
    assert subfield_rank == 4
    result = {'production_size_polynomial_checks_passed': True,
              'main_coordinates': 144, 'quotient_coordinates': 72,
              'query_points': 64, 'quotient_cosets_exercised': 8,
              'outside_quotient_coset_exercised': True,
              'balanced_quotient_identity_preserved': True,
              'complete_aggregate_difference_cancelled': True,
              'randomizer_degree_below': 256, 'residual_coefficients_at_most': 184, 'private_trace_mask_dimension':192, 'runtime_PCS_disclosure_budget':80, 'execution_vanishing_degree':64,
              'full_degree_batching_rank': 8, 'proper_subfield_batching_rank': subfield_rank,
              'randomizer_kernel_rank': 8,
              'scope': 'deterministic finite arithmetic vector for the mask-transport lemmas'}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


def sum_polynomials(items):
    out = [0]
    for value in items:
        out = add(out, value)
    return out


if __name__ == '__main__':
    main()

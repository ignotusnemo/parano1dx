#!/usr/bin/env python3
"""Cost specified native hash constructions after Boolean specialization.

AND count and AND depth describe these DAGs. The four-T temporary-AND
mapping includes measured cleanup. Full quantum gate count, measurement
latency, lookup costs and amortized batch minima require further costing.
Requires PyCryptodome on the normal Python module search path, including
any locations supplied through PYTHONPATH.
"""

import argparse
import hashlib
import json
import sys
from fractions import Fraction
from pathlib import Path


FIELD_PRIME = 2130706433
SELECTED_PRICE = 1 << 20
SUFFICIENT_PRICE = 682672
MASK32 = (1 << 32) - 1


class DAG:
    """Binary XOR/AND DAG with complemented edges and structural CSE.

    Literal zero and one are constants. A node literal is twice its ID,
    with the low bit indicating complement. XOR complements are extracted
    to the result. AND retains the polarities of its two controls.
    """

    def __init__(self):
        self.nodes = [('constant', 0, 0)]
        self.and_depth = [0]
        self.boolean_depth = [0]
        self.cache = {}
        self.variables = []

    def variable(self):
        index = len(self.variables)
        ident = len(self.nodes)
        self.nodes.append(('variable', index, 0))
        self.and_depth.append(0)
        self.boolean_depth.append(0)
        literal = 2 * ident
        self.variables.append(literal)
        return literal

    def gate(self, kind, a, b):
        a, b = sorted((a, b))
        key = kind, a, b
        if key in self.cache:
            return self.cache[key]
        ident = len(self.nodes)
        self.nodes.append(key)
        self.and_depth.append(
            max(self.and_depth[a >> 1], self.and_depth[b >> 1])
            + (kind == 'AND')
        )
        self.boolean_depth.append(
            max(self.boolean_depth[a >> 1], self.boolean_depth[b >> 1]) + 1
        )
        literal = 2 * ident
        self.cache[key] = literal
        return literal

    def xor(self, a, b):
        if a < 2:
            return b ^ a
        if b < 2:
            return a ^ b
        if a >> 1 == b >> 1:
            return (a ^ b) & 1
        complement = (a ^ b) & 1
        return self.gate('XOR', a & ~1, b & ~1) ^ complement

    def and_(self, a, b):
        if a == 0 or b == 0 or a == (b ^ 1):
            return 0
        if a == 1:
            return b
        if b == 1 or a == b:
            return a
        return self.gate('AND', a, b)

    def xor_many(self, values):
        result = 0
        for value in values:
            result = self.xor(result, value)
        return result

    def live(self, outputs):
        live = set()
        pending = [value >> 1 for value in outputs if value >= 2]
        while pending:
            ident = pending.pop()
            if ident in live:
                continue
            live.add(ident)
            kind, a, b = self.nodes[ident]
            if kind != 'variable':
                if a >= 2:
                    pending.append(a >> 1)
                if b >= 2:
                    pending.append(b >> 1)
        return sorted(live)

    def metrics(self, outputs):
        live = self.live(outputs)
        and_count = sum(self.nodes[i][0] == 'AND' for i in live)
        xor_count = sum(self.nodes[i][0] == 'XOR' for i in live)
        depth = max((self.and_depth[v >> 1] for v in outputs), default=0)
        product = 4 * and_count * depth
        return {
            'output_bits': len(outputs),
            'live_variable_bits': sum(self.nodes[i][0] == 'variable' for i in live),
            'live_AND_nodes': and_count,
            'live_XOR_nodes': xor_count,
            'AND_depth': depth,
            'Boolean_binary_gate_depth': max(
                (self.boolean_depth[v >> 1] for v in outputs), default=0
            ),
            'complemented_output_bits': sum(v & 1 for v in outputs),
            'clean_XOR_T_count': 4 * and_count,
            'clean_XOR_T_depth_model': depth,
            'T_only_gate_depth_product': product,
            'product_over_selected_price': ratio(product, SELECTED_PRICE),
            'product_over_sufficient_price': ratio(product, SUFFICIENT_PRICE),
        }

    def evaluate_batch(self, outputs, assignments):
        """Evaluate all validation cases as bit-packed Boolean words."""
        mask = (1 << len(assignments)) - 1
        packed_inputs = [
            sum(((case[i] & 1) << j) for j, case in enumerate(assignments))
            for i in range(len(self.variables))
        ]
        values = [0] * len(self.nodes)

        def value(literal):
            return values[literal >> 1] ^ (mask if literal & 1 else 0)

        for ident in self.live(outputs):
            kind, a, b = self.nodes[ident]
            if kind == 'variable':
                values[ident] = packed_inputs[a]
            elif kind == 'XOR':
                values[ident] = value(a) ^ value(b)
            else:
                values[ident] = value(a) & value(b)
        packed_outputs = [value(v) for v in outputs]
        return [
            [(v >> j) & 1 for v in packed_outputs]
            for j in range(len(assignments))
        ]


def ratio(numerator, denominator):
    value = Fraction(numerator, denominator)
    return {
        'numerator': value.numerator,
        'denominator': value.denominator,
        'decimal': float(value),
    }


KECCAK_ROTATIONS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
KECCAK_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def rotate_left(word, amount):
    return [word[(i - amount) % len(word)] for i in range(len(word))]


def word_xor(dag, *words):
    return [dag.xor_many(bits) for bits in zip(*words)]


def keccak_f(dag, state_bits):
    a = [state_bits[64 * i:64 * (i + 1)] for i in range(25)]
    for constant in KECCAK_CONSTANTS:
        columns = [word_xor(dag, *(a[x + 5 * y] for y in range(5))) for x in range(5)]
        deltas = [
            word_xor(dag, columns[(x - 1) % 5], rotate_left(columns[(x + 1) % 5], 1))
            for x in range(5)
        ]
        a = [word_xor(dag, a[x + 5 * y], deltas[x]) for y in range(5) for x in range(5)]
        b = [None] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(
                    a[x + 5 * y], KECCAK_ROTATIONS[x][y]
                )
        a = [
            [
                dag.xor(b[x + 5 * y][z], dag.and_(
                    b[(x + 1) % 5 + 5 * y][z] ^ 1,
                    b[(x + 2) % 5 + 5 * y][z],
                ))
                for z in range(64)
            ]
            for y in range(5) for x in range(5)
        ]
        a[0] = [v ^ ((constant >> z) & 1) for z, v in enumerate(a[0])]
    return [v for lane in a for v in lane]


def bits_from_bytes(data):
    return [(byte >> bit) & 1 for byte in data for bit in range(8)]


def bytes_from_bits(bits):
    return bytes(sum(bits[i + b] << b for b in range(8)) for i in range(0, len(bits), 8))


def nonce_variables(dag):
    return [dag.variable() for _ in range(31)] + [0]


def native_keccak(dag, prefix):
    state = bits_from_bytes(prefix) + nonce_variables(dag)
    state += bits_from_bytes(b'\x01' + bytes(66) + b'\x80')
    state += [0] * 512
    assert len(state) == 1600
    return keccak_f(dag, state)[:256]


SHA_CONSTANTS = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
SHA_INITIAL = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]


def rotate_right_int(value, amount):
    return ((value >> amount) | (value << (32 - amount))) & MASK32


def sha_compress_int(initial, block):
    """Classical fixed-prefix midstate, with no message padding added."""
    words = [int.from_bytes(block[4*i:4*i+4], 'big') for i in range(16)]
    for i in range(16, 64):
        x, y = words[i - 15], words[i - 2]
        s0 = rotate_right_int(x, 7) ^ rotate_right_int(x, 18) ^ (x >> 3)
        s1 = rotate_right_int(y, 17) ^ rotate_right_int(y, 19) ^ (y >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & MASK32)
    a, b, c, d, e, f, g, h = initial
    for constant, word in zip(SHA_CONSTANTS, words):
        s1 = rotate_right_int(e, 6) ^ rotate_right_int(e, 11) ^ rotate_right_int(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + s1 + ch + constant + word) & MASK32
        s0 = rotate_right_int(a, 2) ^ rotate_right_int(a, 13) ^ rotate_right_int(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) & MASK32
        a, b, c, d, e, f, g, h = (t1 + t2) & MASK32, a, b, c, (d + t1) & MASK32, e, f, g
    return [(u + v) & MASK32 for u, v in zip(initial, (a, b, c, d, e, f, g, h))]


def constant_word(value):
    return [(value >> i) & 1 for i in range(32)]


def rotate_right(word, amount):
    return [word[(i + amount) % 32] for i in range(32)]


def shift_right(word, amount):
    return word[amount:] + [0] * amount


def add_ripple(dag, left, right):
    """One-AND majority recurrence for each required carry bit."""
    carry = 0
    result = []
    for i, (a, b) in enumerate(zip(left, right)):
        propagate = dag.xor(a, b)
        result.append(dag.xor(propagate, carry))
        if i != 31:
            carry = dag.xor(a, dag.and_(propagate, dag.xor(a, carry)))
    return result


def add_prefix(dag, left, right):
    """Kogge-Stone binary carry prefix, with disjoint generate XOR."""
    propagate = word_xor(dag, left, right)
    p = propagate[:31]
    g = [dag.and_(a, b) for a, b in zip(left[:31], right[:31])]
    for distance in (1, 2, 4, 8, 16):
        old_p, old_g = p, g
        p = old_p[:]
        g = old_g[:]
        for i in range(distance, 31):
            g[i] = dag.xor(old_g[i], dag.and_(old_p[i], old_g[i - distance]))
            p[i] = dag.and_(old_p[i], old_p[i - distance])
    return [propagate[0]] + [dag.xor(propagate[i], g[i - 1]) for i in range(1, 32)]


def add_many(dag, adder, words):
    constant = 0
    variable_words = []
    for word in words:
        if all(v < 2 for v in word):
            constant = (constant + sum(v << i for i, v in enumerate(word))) & MASK32
        else:
            variable_words.append(word)
    if constant or not variable_words:
        variable_words.append(constant_word(constant))
    while len(variable_words) > 1:
        variable_words = [
            adder(dag, variable_words[i], variable_words[i + 1])
            if i + 1 < len(variable_words) else variable_words[i]
            for i in range(0, len(variable_words), 2)
        ]
    return variable_words[0]


def native_sha256(dag, prefix, adder):
    midstate = sha_compress_int(SHA_INITIAL, prefix)
    nonce = nonce_variables(dag)
    block = [nonce[i:i+8] for i in range(0, 32, 8)]
    block += [bits_from_bytes(bytes([v])) for v in b'\x80' + bytes(51) + (544).to_bytes(8, 'big')]
    assert len(block) == 64
    words = [
        [block[4*i + 3 - j//8][j % 8] for j in range(32)]
        for i in range(16)
    ]
    for i in range(16, 64):
        x, y = words[i - 15], words[i - 2]
        s0 = word_xor(dag, rotate_right(x, 7), rotate_right(x, 18), shift_right(x, 3))
        s1 = word_xor(dag, rotate_right(y, 17), rotate_right(y, 19), shift_right(y, 10))
        words.append(add_many(dag, adder, [words[i - 16], s0, words[i - 7], s1]))
    initial = [constant_word(v) for v in midstate]
    a, b, c, d, e, f, g, h = initial
    for constant, word in zip(SHA_CONSTANTS, words):
        s1 = word_xor(dag, rotate_right(e, 6), rotate_right(e, 11), rotate_right(e, 25))
        ch = [dag.xor(z, dag.and_(x, dag.xor(y, z))) for x, y, z in zip(e, f, g)]
        t1 = add_many(dag, adder, [h, s1, ch, constant_word(constant), word])
        s0 = word_xor(dag, rotate_right(a, 2), rotate_right(a, 13), rotate_right(a, 22))
        maj = [dag.xor(x, dag.and_(dag.xor(x, y), dag.xor(x, z))) for x, y, z in zip(a, b, c)]
        t2 = add_many(dag, adder, [s0, maj])
        a, b, c, d, e, f, g, h = (
            adder(dag, t1, t2), a, b, c, adder(dag, d, t1), e, f, g
        )
    final = [adder(dag, u, v) for u, v in zip(initial, (a, b, c, d, e, f, g, h))]
    return [word[(3 - byte) * 8 + bit] for word in final for byte in range(4) for bit in range(8)]


PROJECTIONS = {
    'full256': list(range(256)),
    'grind12': list(range(240, 244)) + list(range(248, 256)),
    'last_byte_low_bit': [248],
}


def nonce_cases():
    cases = [0, 1, 2, FIELD_PRIME // 2, FIELD_PRIME - 2, FIELD_PRIME - 1,
             (1 << 24) - 1, 1 << 24, 1 << 30]
    for i in range(7):
        seed = b'parano1dx-hash-circuit-nonce-v1' + i.to_bytes(4, 'little')
        cases.append(int.from_bytes(hashlib.sha256(seed).digest()[:4], 'little') % FIELD_PRIME)
    assert len(cases) == len(set(cases))
    return cases


def check_primitives():
    dag = DAG()
    a, b = dag.variable(), dag.variable()
    assert dag.xor(a, b) == dag.xor(b, a)
    assert dag.and_(a, b) == dag.and_(b, a)
    assert dag.xor(a, a) == 0
    assert dag.xor(a, a ^ 1) == 1
    assert dag.and_(a, a ^ 1) == 0
    outputs = [dag.xor(a ^ 1, b), dag.and_(a ^ 1, b), dag.xor(dag.xor(a, b), 1)]
    assignments = [[x, y] for x in range(2) for y in range(2)]
    assert dag.evaluate_batch(outputs, assignments) == [
        [(x ^ 1) ^ y, (x ^ 1) & y, x ^ y ^ 1] for x, y in assignments
    ]
    for adder in (add_ripple, add_prefix):
        arithmetic_dag = DAG()
        left = [arithmetic_dag.variable() for _ in range(32)]
        right = [arithmetic_dag.variable() for _ in range(32)]
        outputs = adder(arithmetic_dag, left, right)
        pairs = [(0, 0), (MASK32, 1), (MASK32, MASK32), (0x55555555, 0xAAAAAAAA),
                 (0x7FFFFFFF, 1), (0x89ABCDEF, 0x76543211)]
        assignments = [constant_word(x) + constant_word(y) for x, y in pairs]
        got = arithmetic_dag.evaluate_batch(outputs, assignments)
        assert [sum(v << i for i, v in enumerate(bits)) for bits in got] == [
            (x + y) & MASK32 for x, y in pairs
        ]


def phase_output_audit(dag, output, assignments, expected_bits):
    """Expand an output XOR cone into signed CZ and input Z phases.

    XOR terms cancel over F2. A remaining AND becomes a phase on its
    actual control literals. Only the controls' dependency union needs
    data computation. A fixed output complement gives a global phase.
    """
    parity = [False] * len(dag.nodes)
    if output >= 2:
        parity[output >> 1] = True
    constant = bool(output & 1)
    frontier = []
    for ident in range(len(dag.nodes) - 1, 0, -1):
        if not parity[ident]:
            continue
        kind, a, b = dag.nodes[ident]
        if kind == 'XOR':
            for literal in (a, b):
                constant ^= bool(literal & 1)
                if literal >= 2:
                    parity[literal >> 1] ^= True
        else:
            frontier.append(ident)

    and_frontier = [i for i in frontier if dag.nodes[i][0] == 'AND']
    variable_frontier = [i for i in frontier if dag.nodes[i][0] == 'variable']
    assert len(and_frontier) + len(variable_frontier) == len(frontier)
    data_outputs = [literal for ident in and_frontier for literal in dag.nodes[ident][1:]]
    data_metrics = dag.metrics(data_outputs)

    # Check the parity identity against the original bit on the same
    # assignments. Then check the actual signed-control CZ/Z expression.
    frontier_bits = dag.evaluate_batch([2 * i for i in frontier], assignments)
    for bits, expected in zip(frontier_bits, expected_bits):
        assert int(constant) ^ (sum(bits) & 1) == expected
    controls_and_variables = data_outputs + [2 * i for i in variable_frontier]
    phase_inputs = dag.evaluate_batch(controls_and_variables, assignments)
    for bits, expected in zip(phase_inputs, expected_bits):
        phase = int(constant)
        for i in range(len(and_frontier)):
            phase ^= bits[2 * i] & bits[2 * i + 1]
        phase ^= sum(bits[len(data_outputs):]) & 1
        assert phase == expected

    data_count = data_metrics['live_AND_nodes'] + data_metrics['live_XOR_nodes']
    data_depth = data_metrics['AND_depth']
    phase_count = len(frontier)
    frontier_digest = hashlib.sha256(json.dumps(
        {'global_phase_bit': int(constant), 'positive_node_ids': frontier},
        separators=(',', ':'),
    ).encode()).hexdigest()
    return {
        'AND': data_metrics['live_AND_nodes'],
        'XOR': data_metrics['live_XOR_nodes'],
        'AND_depth': data_depth,
        'binary_depth': data_metrics['Boolean_binary_gate_depth'],
        'data_gate_count': data_count,
        'frontier_CZ_phases': len(and_frontier),
        'frontier_Z_phases': len(variable_frontier),
        'frontier_complemented_control_literals': sum(v & 1 for v in data_outputs),
        'frontier_sha256': frontier_digest,
        'global_phase_bit': int(constant),
        'data_only_conservative_gate_depth': data_count * data_depth,
        'gate_count_with_phase_frontier': data_count + phase_count,
        'phase_depth_conservative': data_depth + 1,
        'gate_depth_with_phase_frontier': (data_count + phase_count) * (data_depth + 1),
        'validation_cases': len(assignments),
        'frontier_parity_identity_passed': True,
        'signed_control_phase_identity_passed': True,
        'cost_role': 'conservative data accounting of this fixed layout with stated costs omitted',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keccak-only', action='store_true')
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    import Crypto
    from Crypto.Hash import keccak

    check_primitives()
    symbolic_dag = DAG()
    symbolic_outputs = keccak_f(symbolic_dag, [symbolic_dag.variable() for _ in range(1600)])
    symbolic_metrics = symbolic_dag.metrics(symbolic_outputs)
    assert symbolic_metrics['live_AND_nodes'] == 38400, symbolic_metrics
    assert symbolic_metrics['AND_depth'] == 24, symbolic_metrics
    print('Full symbolic Keccak: 38400 AND, AND-depth 24', flush=True)

    prefixes = [
        ('zero', bytes(64)),
        ('ff', b'\xff' * 64),
        ('sha512_deterministic', hashlib.sha512(b'parano1dx-hash-circuit-prefix-v1').digest()),
    ]
    cases = nonce_cases()
    assignments = [[(n >> bit) & 1 for bit in range(31)] for n in cases]
    builders = [('Keccak256', 'temporary_AND_DAG', native_keccak)]
    if not args.keccak_only:
        builders += [
            ('SHA256', 'ripple_majority', lambda d, p: native_sha256(d, p, add_ripple)),
            ('SHA256', 'Kogge_Stone_prefix', lambda d, p: native_sha256(d, p, add_prefix)),
        ]
    rows = []
    phase_rows = []
    for name, prefix in prefixes:
        messages = [prefix + n.to_bytes(4, 'little') for n in cases]
        references = {
            'Keccak256': [keccak.new(digest_bits=256, data=m).digest() for m in messages],
            'SHA256': [hashlib.sha256(m).digest() for m in messages],
        }
        # The unspecialized reference is independently instantiated on all
        # 1600 symbolic inputs using the same padded native test messages.
        symbolic_assignments = [
            bits_from_bytes(m + b'\x01' + bytes(66) + b'\x80' + bytes(64))
            for m in messages
        ]
        symbolic_got = symbolic_dag.evaluate_batch(symbolic_outputs[:256], symbolic_assignments)
        assert [bytes_from_bits(v) for v in symbolic_got] == references['Keccak256']
        for function, adder, builder in builders:
            dag = DAG()
            outputs = builder(dag, prefix)
            assert len(dag.variables) == 31
            got = dag.evaluate_batch(outputs, assignments)
            assert [bytes_from_bits(v) for v in got] == references[function], (function, adder, name)
            metrics = {
                label: dag.metrics([outputs[i] for i in indices])
                for label, indices in PROJECTIONS.items()
            }
            for label, indices in PROJECTIONS.items():
                projected = (
                    got if label == 'full256'
                    else dag.evaluate_batch([outputs[i] for i in indices], assignments)
                )
                for bits, reference in zip(projected, references[function]):
                    expected_bits = bits_from_bytes(reference)
                    assert bits == [expected_bits[i] for i in indices]
            row = {
                'function': function,
                'construction': adder,
                'prefix_sample': name,
                'prefix_hex': prefix.hex(),
                'allocated_DAG_nodes': len(dag.nodes) - 1,
                'projections': metrics,
                'validation_cases': len(cases),
                'validation_passed': True,
                'cost_role': 'specified sampled construction with constant propagation and pruning',
            }
            rows.append(row)
            phase_rows.append({
                'function': function,
                'construction': adder,
                'prefix_sample': name,
                **phase_output_audit(dag, outputs[248], assignments, [bits[248] for bits in got]),
            })
            print(function, adder, name, json.dumps({
                label: (m['live_AND_nodes'], m['AND_depth'], m['T_only_gate_depth_product'])
                for label, m in metrics.items()
            }), flush=True)

    sampled_ranges = []
    for function, construction, _ in builders:
        matching = [r for r in rows if (r['function'], r['construction']) == (function, construction)]
        for projection in PROJECTIONS:
            measurements = [r['projections'][projection] for r in matching]
            cheapest = min(matching, key=lambda r: r['projections'][projection]['T_only_gate_depth_product'])
            sampled_ranges.append({
                'function': function,
                'construction': construction,
                'projection': projection,
                'prefix_sample_count': len(matching),
                'live_AND_nodes_range': [min(m['live_AND_nodes'] for m in measurements),
                                         max(m['live_AND_nodes'] for m in measurements)],
                'AND_depth_range': [min(m['AND_depth'] for m in measurements),
                                    max(m['AND_depth'] for m in measurements)],
                'T_only_product_range': [min(m['T_only_gate_depth_product'] for m in measurements),
                                        max(m['T_only_gate_depth_product'] for m in measurements)],
                'cheapest_observed_prefix_sample': cheapest['prefix_sample'],
                'scope': 'observations over these three prefixes and this specified construction',
            })

    result = {
        'title': 'Native fixed-prefix hash circuit construction accounting',
        'date': '2026-11-09',
        'generator': Path(__file__).name,
        'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'scope': 'three public prefix samples and specified Boolean DAG constructions',
        'sample_minimum_is_universal_lower_bound': False,
        'message': {
            'bytes': 68, 'prefix_bytes': 64, 'nonce_encoding': '32-bit little-endian',
            'variable_nonce_bits': 31, 'fixed_nonce_bit': {'index': 31, 'value': 0},
            'field_prime': FIELD_PRIME,
            'canonical_domain': '0 <= nonce < field_prime',
            'circuit_domain': 'all 31-bit nonces, a superset of the canonical domain',
            'canonical_range_check_costed': False,
            'Keccak256_rate_bytes': 136, 'Keccak256_delimiter_hex': '01',
            'Keccak256_permutations': 1,
            'SHA256_total_compressions': 2,
            'SHA256_online_compressions_after_fixed_prefix_reuse': 1,
            'SHA256_online_includes': ['64 rounds', 'message schedule', 'digest feed-forward'],
        },
        'DAG_rules': [
            'Literal low bit records complement, with zero and one represented directly.',
            'Local constant propagation and identical or complementary input cancellation.',
            'Commutative binary gate canonicalization and structural common-subexpression elimination.',
            'XOR input complements move to the output literal.',
            'Dead-output-cone pruning precedes every projection count.',
            'Associative XOR resynthesis and global Boolean minimization are not applied.',
            'SHA additions combine constant operands and use a balanced tree for multiple terms.',
            'Ripple carry uses the one-AND identity maj(a,b,c)=a XOR ((a XOR b) AND (a XOR c)).',
            'Parallel carry uses five Kogge-Stone prefix levels for 32-bit words.',
        ],
        'metric_model': {
            'AND_XOR_counts': 'live classical Boolean nodes, with NOT carried by complemented edges',
            'AND_depth': 'maximum number of AND nodes along a live dependency path',
            'Boolean_binary_gate_depth': 'depth counting each AND or XOR node once, not full quantum depth',
            'clean_XOR_mapping': '|x>|y>|0^k> -> |x>|y XOR f(x)>|0^k>',
            'T_per_temporary_AND': 4,
            'T_per_measured_AND_uncompute': 0,
            'T_depth_model': 'AND depth with sufficient helper qubits and Clifford fanout scheduling',
            'T_only_product': '4 * live_AND_nodes * AND_depth',
            'automatic_compute_uncompute_T_doubling': False,
            'omitted_from_T_only_accounting': [
                'Clifford fanout and XOR implementation', 'output copying',
                'complement control handling', 'measurement and classical correction latency',
                'reset and workspace scheduling', 'coherent prefix preparation or lookup',
                'acceptance comparator', 'range enforcement', 'multi-query sharing and batch amortization',
            ],
            'full_logical_gate_depth_established': False,
            'native_batch_minimum_established': False,
        },
        'symbolic_Keccak_full1600': symbolic_metrics,
        'projection_bit_indices': PROJECTIONS,
        'projection_definition': 'Index 8*byte+bit uses least significant bit first within each digest byte.',
        'grind12_definition': 'digest byte 30 low four bits and digest byte 31 all eight bits',
        'one_bit_definition': 'digest byte 31 low bit',
        'SHA_projection_scope': 'same byte projections as a component-cost comparison',
        'validation': {
            'nonce_values': cases,
            'nonce_sample_seed': 'parano1dx-hash-circuit-nonce-v1',
            'prefix_sample_seed': 'parano1dx-hash-circuit-prefix-v1',
            'reference_libraries': [
                {'name': 'hashlib', 'version': 'Python ' + sys.version.split()[0],
                 'algorithm': 'SHA-256', 'implementation': 'hashlib.sha256'},
                {'name': 'PyCryptodome', 'version': Crypto.__version__,
                 'algorithm': 'Keccak-256', 'implementation': 'Crypto.Hash.keccak'},
            ],
            'primitives_and_adders_passed': True,
            'full_symbolic_Keccak_padded_native_digests_passed': True,
            'full256_and_all_projections_passed': True,
            'projected_DAGs_evaluated_after_pruning': True,
            'one_bit_phase_frontier_identity_passed': True,
            'signed_control_phase_identity_passed': True,
            'phase_identity_validation_cases': len(phase_rows) * len(cases),
            'validated_hash_evaluations': len(rows) * len(cases),
            'symbolic_Keccak_validation_evaluations': len(prefixes) * len(cases),
        },
        'selected_price': SELECTED_PRICE,
        'sufficient_price_at_GD_2pow170': SUFFICIENT_PRICE,
        'constructions': rows,
        'sampled_ranges': sampled_ranges,
        'phase_rows': phase_rows,
        'minimum_sampled_phase_data': min(
            phase_rows, key=lambda r: r['data_only_conservative_gate_depth']
        ),
        'one_bit_phase_method': {
            'interface': '|x> -> (-1)^h(x)|x> with cleaned work registers',
            'output_bit': 'digest byte 31 low bit, index 248',
            'identity': '(-1)^(a XOR b) = (-1)^a * (-1)^b',
            'frontier': 'Expand XOR nodes over F2 in reverse topological order and cancel repeated positive node IDs.',
            'AND_frontier': 'Apply CZ on the actual signed control literals of each frontier AND.',
            'variable_frontier': 'Apply Z to each frontier variable.',
            'data_dependencies': 'Compute the union of dependencies of all frontier AND controls, then apply phases and clean work registers.',
            'complements': 'XOR complements toggle the global constant. Complemented AND controls keep their actual signed-control phases.',
            'global_phase_removal_scope': 'Only a fixed global phase for each fixed classical prefix may be dropped. Coherent prefix selection must retain any relative phase.',
            'data_only_price': '(data_AND_nodes + data_XOR_nodes) * data_AND_depth',
            'phase_frontier_price': '(data_AND_nodes + data_XOR_nodes + frontier_CZ_phases + frontier_Z_phases) * (data_AND_depth + 1)',
            'phase_frontier_depth_scope': 'One extra phase layer is an optimistic proxy that grants free control fanout.',
            'omitted_costs': [
                'all CZ and Z phases in the data-only proxy',
                'complemented-control phase corrections',
                'cleanup and workspace release',
                'Clifford fanout and its scheduling',
                'measurement, reset and classical correction latency',
                'coherent prefix preparation or lookup',
            ],
            'scope': 'conservative accounting of the specified sampled layouts, with clean-XOR phase kickback also available from the one-bit projection',
            'full_quantum_gate_depth_established': False,
            'universal_minimum_established': False,
        },
        'remaining_work': [
            'Assess additional prefix values and other circuit architectures.',
            'Compile full logical gate counts and scheduled depth in a fixed gate library.',
            'Cost native acceptance predicates and any further output-cone simplifications.',
            'Account for coherent prefix selection, sharing, lookup and amortized batches.',
            'Apply the complete success evaluator to any assessed batch price.',
        ],
        'primary_sources': [
            {'url': 'https://arxiv.org/pdf/2006.03845v1',
             'locator': 'Table 1 AND count 38400 and depth 24, Table 2 T count 153600 and T-depth 24'},
            {'url': 'https://msoeken.github.io/papers/2019_iccad.pdf',
             'locator': 'Abstract and Section II-D, clean XOR oracles with four-T computation and zero-T measured uncomputation'},
            {'url': 'https://keccak.team/keccak_specs_summary.html',
             'locator': 'Keccak-f pseudocode and sponge byte padding'},
            {'url': 'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf',
             'locator': 'Sections 5.1.1 and 6.2, SHA-256 padding and compression'},
        ],
        'reproduce': 'python3 research/security/check_hash_circuits.py',
    }
    destination = Path(__file__).with_name('hash-circuit-checks.json')
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print('Wrote', destination, flush=True)


if __name__ == '__main__':
    main()

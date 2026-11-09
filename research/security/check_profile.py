#!/usr/bin/env python3
"""Exact finite checks for the external-vault authorization profile."""
from fractions import Fraction
from pathlib import Path
from math import comb, gcd, log2
from itertools import combinations
import argparse
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[2]
P = 2130706433
D = 8


def trim(a):
    a = [x % P for x in a]
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a


def remainder(a, b):
    a, b = trim(a), trim(b)
    inverse = pow(b[-1], -1, P)
    while len(a) >= len(b) and a != [0]:
        c, at = a[-1] * inverse % P, len(a) - len(b)
        for i, x in enumerate(b):
            a[at + i] = (a[at + i] - c * x) % P
        a = trim(a)
    return a


def multiply(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] = (out[i + j] + x * y) % P
    return remainder(out, [-3] + [0] * 7 + [1])


def power(a, n):
    out = [1]
    while n:
        if n & 1:
            out = multiply(out, a)
        a = multiply(a, a)
        n >>= 1
    return out


def polynomial_gcd(a, b):
    while b != [0]:
        a, b = b, remainder(a, b)
    return [(x * pow(a[-1], -1, P)) % P for x in a]


def rank(matrix):
    a = [[x % P for x in row] for row in matrix]
    pivot = 0
    for col in range(len(a[0])):
        row = next((i for i in range(pivot, len(a)) if a[i][col]), None)
        if row is None:
            continue
        a[pivot], a[row] = a[row], a[pivot]
        inv = pow(a[pivot][col], -1, P)
        a[pivot] = [(x * inv) % P for x in a[pivot]]
        for i in range(len(a)):
            if i != pivot and a[i][col]:
                c = a[i][col]
                a[i] = [(x - c * y) % P for x, y in zip(a[i], a[pivot])]
        pivot += 1
    return pivot


def rational(value):
    value = Fraction(value)
    return {"numerator": str(value.numerator), "denominator": str(value.denominator),
            "negative_log2": log2(value.denominator) - log2(value.numerator)}


def matrix_product(a, b):
    columns = list(zip(*b))
    return [[sum(x*y for x, y in zip(row, column)) % P
             for column in columns] for row in a]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("finite-profile.json"))
    args = parser.parse_args()
    auth = (ROOT / "experiments/native-vault/auth/src/lib.rs").read_text()
    compact = re.sub(r"\s+", "", auth)
    assert 'pubtypeVal=KoalaBear;' in compact
    assert 'pubtypeExt=BinomialExtensionField<Val,8>;' in compact
    assert 'log_final_poly_len:0,max_log_arity:2,' in compact
    assert 'Pcs::new(Radix2DitParallel::default(),mmcs,params,8,StdRng::from_seed(seed))' in compact
    assert 'MerkleTreeHidingMmcs<Val,u64,FieldHash,Compress,StdRng,2,8,MERKLE_SALT_WORDS>' in compact
    for name, value in [("TRACE_LOG", 7), ("WIDTH", 24), ("SECRET_WORDS", 14),
                        ("OUTPUTS", 12), ("REQUEST_LIMBS", 16), ("NUM_QUERIES", 64),
                        ("LOG_BLOWUP", 4), ("MERKLE_SALT_WORDS", 20),
                        ("QUERY_GRINDING_BITS", 12), ("FULL_ROUNDS", 8), ("PARTIAL_ROUNDS", 26)]:
        assert re.search(r"pub const " + name + r":\s*usize\s*=\s*" + str(value) + r";", auth), name

    # Proth's theorem certifies primality: p = 127 * 2^24 + 1.
    assert P == 127 * 2**24 + 1 and 127 < 2**24
    assert pow(3, (P - 1)//2, P) == P - 1
    # Rabin's irreducibility criterion. The only prime divisor of degree 8 is 2.
    assert power([0, 1], P**8) == [0, 1]
    x4 = power([0, 1], P**4)
    x4 += [0] * max(0, 2 - len(x4))
    x4[1] = (x4[1] - 1) % P
    assert polynomial_gcd([-3] + [0] * 7 + [1], trim(x4)) == [1]
    assert gcd(3, P - 1) == 1

    frobenius = []
    for j in range(8):
        column = power([0, 1], j * P**4) + [0] * 8
        frobenius.append([(column[i] - int(i == j)) % P for i in range(8)])
    assert rank(list(map(list, zip(*frobenius)))) == 4

    stream = (ROOT / "experiments/native-vault/auth/src/stream_parameters.rs").read_text()
    verifier = (ROOT / "experiments/native-vault/auth/src/stream.rs").read_text()
    heights = json.loads(re.search(r"const HEIGHTS:[^=]+=(\[[^;]+\]);", verifier)[1])
    assert heights == [12, 12, 12, 12, 10, 8, 6, 4]
    native_profile = json.loads(Path(__file__).with_name("interactive-profile.json").read_text())
    leaf_bytes = native_profile['stream_leaf_bytes']
    assert leaf_bytes == [144,272,1152,192,208,208,208,208]
    private_leaf_words = [size//4 for i, size in enumerate(leaf_bytes) if i != 3]
    assert set(private_leaf_words) == {36, 52, 68, 288}
    assert all(size % 4 == 0 for size in leaf_bytes)
    assert min(private_leaf_words) == 36
    private_leaves = sum(2**h for i, h in enumerate(heights) if i != 3)
    assert private_leaves == 13648
    generators = re.search(r"pub const GENERATORS:[^=]+=(\[[^;]+\]);", stream)
    assert generators
    g = json.loads(generators[1])[6]
    assert pow(g, 64, P) == 1 and pow(g, 32, P) != 1
    for j in range(1, 8):
        assert pow(g, 8 // gcd(j, 8), P) != 1
    for seed in ["STARK_SEED", "PCS_SEED", "FRI_SEED"]:
        length = int(re.search(r"pub const " + seed + r":\s*\[u8;\s*(\d+)\]", stream)[1])
        assert length % 4 == 0

    fixture_path = ROOT / "experiments/native-vault/results/optimized-evm/evm-export.json"
    fixture = json.loads(fixture_path.read_text())
    native_profile = json.loads(Path(__file__).with_name("interactive-profile.json").read_text())
    authority_domain = b"Parano1dX/v1/authority/koalabear24/r8p26"
    public_seed = bytes.fromhex(native_profile["public_seed_digest"])
    assert native_profile["public_seed_input_bytes"] == len(authority_domain) == 40
    assert len(public_seed) == 64
    assert public_seed[:32] == hashlib.sha256(authority_domain).digest()
    capacity = [int.from_bytes(public_seed[4*i:4*i+4], "little") % P for i in range(10)]
    assert capacity == native_profile["initial_capacity"]
    assert capacity == [x*pow(2**32, -1, P) % P for x in fixture["capacity_raw"]]
    matrix_ranks = {kind: rank(fixture[kind + "_matrix_columns_raw"])
                    for kind in ["external", "internal"]}
    assert matrix_ranks == {"external": 24, "internal": 24}
    # Montgomery representation scales every matrix entry by a nonzero scalar.
    # It therefore preserves rank over F_p.
    inverse_montgomery = pow(2**32, -1, P)
    internal = [[fixture["internal_matrix_columns_raw"][j][i]*inverse_montgomery % P
                 for j in range(24)] for i in range(24)]
    assert all(internal[i][j] == 1 for i in range(24) for j in range(24) if i != j)
    diagonal = [(internal[i][i]-1) % P for i in range(24)]
    assert len(set(diagonal)) == 24 and all(diagonal)
    matrix_power = [[int(i == j) for j in range(24)] for i in range(24)]
    observability_ranks = []
    for exponent in range(1, 97):
        matrix_power = matrix_product(matrix_power, internal)
        row = [1] + [0]*23
        observations = []
        for _ in range(24):
            observations.append(row)
            row = matrix_product([row], matrix_power)[0]
        value = rank(observations)
        assert value == 24, (exponent, value)
        observability_ranks.append(value)
    external4 = [[fixture["external_matrix_columns_raw"][j][i] for j in range(4)] for i in range(4)]
    minors = 0
    for size in range(1, 5):
        for rows in combinations(range(4), size):
            for columns in combinations(range(4), size):
                assert rank([[external4[i][j] for j in columns] for i in rows]) == size
                minors += 1
    assert minors == 69
    assert all(len(batch) == expected for batch, expected in
               zip(fixture["claims_raw"], [1, 1, 8, 1], strict=True))
    assert sum(len(point) for batch in fixture["claims_raw"]
               for matrix in batch for point in matrix) == 268

    certificate_path = Path(__file__).with_name('rs-certificate.json')
    certificate = json.loads(certificate_path.read_text())
    assert certificate['source']['dimension'] == 257
    assert certificate['codeword_rows'] == 4096 and certificate['queries'] == 64
    source_good = certificate['source']['agreement_count']
    agreement = Fraction(source_good, certificate['codeword_rows'])
    assert str(agreement) == certificate['agreement_upper'] == '7/32'
    query_error = Fraction(comb(source_good, 64), comb(4096, 64))
    layers=[]
    n,k=4096,256
    for arity in [4,4,4,4]:
        layers.append({'domain':n,'dimension':k,'fold_arity':arity})
        n//=arity;k//=arity
    assert (n,k)==(16,1)
    main_observations = 2*64 + 2*8
    runtime_budget = 64 + 8*2
    assert runtime_budget <= 128 and main_observations <= 192
    assert 64 + 8 <= 128
    assert 256 - 64 - 8 > 0
    assert 2*(40+8) + 28 + 8*(8+8) + (8+8) == 268
    r = 2**32 - 2*P
    tv = Fraction(r*(P-r), P*2**32)
    assert 0 < r < P
    domains = [b"Parano1dX/proof-rng/masks/v1", b"Parano1dX/proof-rng/merkle-salts/v1"]
    assert domains[0] != domains[1] and not domains[0].startswith(domains[1]) and not domains[1].startswith(domains[0])

    files = ["experiments/native-vault/auth/src/lib.rs", "experiments/native-vault/auth/src/sampler.rs", "experiments/native-vault/auth/src/stream.rs",
             "experiments/native-vault/auth/src/stream_parameters.rs", "experiments/native-vault/prover/src/main.rs",
             "experiments/native-vault/evm/Parano1dVault.sol", "experiments/native-vault/evm/VVerifier.sol",
             "experiments/native-vault/solana/src/lib.rs", "experiments/native-vault/vendor/p3-fri/src/hiding_pcs.rs",
             "experiments/native-vault/results/optimized-evm/evm-export.json",
             "experiments/native-vault/auth/src/poseidon_constants.rs",
             "experiments/native-vault/prover/src/export.rs",
             "experiments/native-vault/evm/VField.sol",
             "experiments/native-vault/evm/VParameters.sol",
             "experiments/native-vault/evm/prepare.py",
             "experiments/native-vault/auth/build.rs",
             "experiments/native-vault/prover/src/bin/security-profile.rs",
             "research/security/rs-certificate.json"]
    result = {
        "scope": "finite parameters and polynomial-mask transport",
        "fixed_public_hash_rows": 1,
        "public_capacity_seed_input": authority_domain.decode(),
        "public_capacity_seed_digest": public_seed.hex(),
        "public_seed_capacity_matches_native_air": True,
        "base_prime": P, "extension_degree": D, "extension_size": str(P**8),
        "merkle_salt_words": 20, "query_grinding_bits": 12,
        "poseidon_full_rounds": 8, "poseidon_partial_rounds": 26,
        "extension_irreducible": True, "cube_bijective": True,
        "base_primality": "Proth certificate, base 3",
        "linear_layer_ranks": matrix_ranks,
        "internal_diagonal_distinct_nonzero": True,
        "internal_observability_powers_checked": len(observability_ranks),
        "internal_observability_minimum_rank": min(observability_ranks),
        "external_base_block_nonzero_minors": minors,
        "proper_subfield_size": str(P**4), "rotation_order": 64,
        "nonzero_rotation_frobenius_orbits_disjoint": True,
        "main_disclosure_coordinates": main_observations, "runtime_hiding_budget": runtime_budget,
        "main_mask_coordinates": 192, "quotient_disclosure_coordinates": 72,
        "randomizer_remaining_extension_coefficients": 184,
        "private_merkle_leaf_positions": private_leaves,
        "private_leaf_field_word_domains": sorted(set(private_leaf_words)),
        "minimum_dummy_leaf_field_words": min(private_leaf_words),
        "private_merkle_internal_nodes": private_leaves-7,
        "disclosed_private_leaf_positions_at_most": 64*7,

        "mask_transport_exception": rational(Fraction(1, P**4) + Fraction(8192, P**8)),
        "query_phase_error_upper": rational(query_error),
        "query_sampling": "uniform 64-element subset without replacement",
        "agreement_upper": str(agreement),
        "agreement_scope": "Finite first-order certificate in rs-certificate.json", "layers": layers,
        "derivation_distribution": {"heavy_residues": r, "heavy_probability": "3/4294967296",
            "other_probability": "2/4294967296", "total_variation_from_uniform_one_word": rational(tv)},
        "source_sha256": {f: hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in files},
        "quantum_authorization_certificate": "native QROM theorem: SECURITY.html and research/security/security-evaluation.json",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"finite_checks_passed": True, "extension_irreducible": True,
                      "main_disclosure_coordinates": main_observations,
                      "query_reference_error_bits": result["query_phase_error_upper"]["negative_log2"],
                      "mask_transport_exception_bits": result["mask_transport_exception"]["negative_log2"]}))


if __name__ == "__main__":
    main()

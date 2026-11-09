#!/usr/bin/env python3
"""Reproduce the Poseidon2 round inequalities and Grain round constants.

The algorithms follow the authors' poseidon2_rust_params.sage. The Grain
stream for 8 full and 23 partial rounds matches the pinned Plonky3 table.
The selected 256-bit classical attack-cost target keeps width 24 and x^3.
Primitive preimage hardness remains an explicit security condition.
"""
from decimal import Decimal, localcontext, ROUND_CEILING, ROUND_FLOOR
from hashlib import sha256
from math import comb
from pathlib import Path
import argparse
import json

ROOT = Path(__file__).resolve().parents[2]
P, WIDTH, ALPHA = 2130706433, 24, 3
REFERENCE = "https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage"


def round_conditions(full, partial, target):
    with localcontext() as ctx:
        ctx.prec = 80
        logp = Decimal(P).ln() / Decimal(2).ln()
        loga = Decimal(ALPHA).ln() / Decimal(2).ln()
        logat = Decimal(WIDTH).ln() / Decimal(ALPHA).ln()
        ceil = lambda x: int(x.to_integral_value(rounding=ROUND_CEILING))
        threshold = int((logp - Decimal(ALPHA - 1) / 2).to_integral_value(
            rounding=ROUND_FLOOR)) * (WIDTH + 1)
        requirements = [6 if target <= threshold else 10,
            1 + ceil(Decimal(min(target, P.bit_length())) / loga) + ceil(logat) - partial,
            ceil(Decimal(min(Decimal(target), logp)) / loga - partial),
            ceil(WIDTH - 1 + min(Decimal(target) / (WIDTH + 1), logp / 2) / loga - partial),
            ceil((WIDTH - 2 + Decimal(target) / (2 * loga) - partial) / (WIDTH - 1))]
        r = WIDTH // 3
        over = (full - 1) * WIDTH + 2 * partial + r + r * (full // 2) + ALPHA
        under = r * (full // 2) + partial + ALPHA
        # Exact equivalent of 2*log2(binomial(over,under)) >= target.
        groebner4 = comb(over, under) ** 2 >= 1 << target
        return full >= max(requirements) and groebner4, requirements, groebner4


def choose_rounds(target):
    candidates = []
    for partial in range(1, 100):
        for full in range(4, 22, 2):
            if round_conditions(full, partial, target)[0]:
                # Standard +2 full rounds and 7.5% partial-round margin.
                safe_full, safe_partial = full + 2, (1075 * partial + 999) // 1000
                candidates.append((WIDTH * safe_full + safe_partial, safe_full, safe_partial))
    _, full, partial = min(candidates)
    return full, partial


def constants(full, partial):
    state = []
    for value, width in [(1, 2), (0, 4), (P.bit_length(), 12), (WIDTH, 12),
                         (full, 10), (partial, 10)]:
        state.extend(map(int, f"{value:0{width}b}"))
    state.extend([1] * 30)
    assert len(state) == 80

    def clock():
        bit = state[62] ^ state[51] ^ state[38] ^ state[23] ^ state[13] ^ state[0]
        state.pop(0)
        state.append(bit)
        return bit

    for _ in range(160):
        clock()
    out = []
    while len(out) < full * WIDTH + partial:
        value = 0
        for _ in range(P.bit_length()):
            while not clock():
                clock()
            value = 2 * value + clock()
        if value < P:
            out.append(value)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    assert choose_rounds(128) == (8, 23)
    assert choose_rounds(256) == (8, 26)
    reference = constants(8, 23)
    reference_hash = sha256(b"".join(x.to_bytes(4, "little") for x in reference)).hexdigest()
    assert reference_hash == "c05b0365a46cb22f12fddb433fd8f483ed16e8350ef886cac6e7b409107c8e98"
    assert reference[:6] == [0x1d0939dc, 0x6d050f8d, 0x628058ad, 0x2681385d,
                             0x3e3c62be, 0x032cfad8]
    full, partial = choose_rounds(256)
    values = constants(full, partial)
    split = WIDTH * full // 2
    first = [values[i:i + WIDTH] for i in range(0, split, WIDTH)]
    internal = values[split:split + partial]
    last = [values[i:i + WIDTH] for i in range(split + partial, len(values), WIDTH)]
    def matrix(name, rows):
        return (f"pub const {name}: [[Val; WIDTH]; {len(rows)}] = Val::new_2d_array([\n"
                + "".join("    [" + ",".join(f"0x{x:08x}" for x in row) + "],\n" for row in rows)
                + "]);\n")
    rust = "// Poseidon2 Grain constants. Reproduce with research/security/poseidon_parameters.py --write.\n"
    rust += matrix("RC_FIRST", first) + matrix("RC_LAST", last)
    rust += f"pub const RC_PARTIAL: [Val; {partial}] = Val::new_array([" + ",".join(
        f"0x{x:08x}" for x in internal) + "]);\n"
    target = ROOT / "experiments/native-vault/auth/src/poseidon_constants.rs"
    if args.write:
        target.write_text(rust)
    else:
        assert target.read_text() == rust
    assessment = {"base_prime": P, "width": WIDTH, "sbox_exponent": ALPHA,
        "classical_round_selection_target_bits": 256, "full_rounds": full,
        "partial_rounds": partial, "active_rows_including_initial_layer": 1 + full + partial,
        "all_six_round_conditions_pass": round_conditions(full, partial, 256)[0],
        "standard_margin_full_rounds": 2, "standard_margin_partial_percent": "7.5",
        "reference": REFERENCE,
        "reference_128_constants_sha256": reference_hash,
        "reference_all_215_constants_match_pinned_backend": True,
        "constants_sha256": sha256(target.read_bytes()).hexdigest(),
        "primitive_condition": "Preimage hardness of the fixed capacity slice and truncated output map.",
        "scope": "Round-selection inequalities and reproducible constants for the selected classical target."}
    if args.write:
        (ROOT / "research/security/poseidon-profile.json").write_text(json.dumps(assessment, indent=2) + "\n")
    print(json.dumps(assessment, indent=2))


if __name__ == "__main__":
    main()

use p3_field::{PrimeCharacteristicRing, PrimeField32, coset::TwoAdicMultiplicativeCoset};
use p3_security::{
    fri::FriRegime,
    shape::{InstanceShape, StarkAirParams},
    stark::proven_security_report,
};
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::{AirLayout, GrindingSites, OpeningShape, StarkSecurityParams};
use parano1dx_vault_auth::{
    AUTH_DOMAIN, AuthorityAir, Ext, LOG_BLOWUP, NUM_QUERIES, NativeHash, TRACE_LOG, Val,
    initial_capacity,
    MERKLE_SALT_WORDS, QUERY_GRINDING_BITS, FULL_ROUNDS, PARTIAL_ROUNDS, stream,
};
use serde_json::json;

fn main() {
    let fri = FriRegime {
        log_blowup: LOG_BLOWUP,
        num_queries: NUM_QUERIES,
        log_final_poly_len: 0,
        max_log_arity: 2,
        commit_pow_bits: 0,
        query_pow_bits: QUERY_GRINDING_BITS,
    };
    let air = AuthorityAir;
    let layout = AirLayout::from_air(&air);
    let domain = TwoAdicMultiplicativeCoset::new(Val::ONE, TRACE_LOG).unwrap();
    // The exact extension size p^8 exceeds 2^247. Taking its floor in bits
    // avoids replacing it by the larger, rounded-up power 2^248.
    let params = StarkSecurityParams::from_air::<Val, Ext, _>(
        fri,
        &air,
        layout,
        domain,
        247,
        256,
        2,
        OpeningShape::hiding(8),
        GrindingSites::NONE,
    );
    let degree_bits = TRACE_LOG + 1;
    let air_shape = StarkAirParams {
        num_constraints: params.num_constraints,
        max_constraint_degree: params.air_max_constraint_degree,
        num_quotient_chunks: params.num_quotient_chunks,
        max_combo: params.max_combo,
    };
    let instance = InstanceShape {
        log_trace_length: degree_bits,
        modulus_bits: params.num_modulus_bits,
        collision_resistance: params.collision_resistance,
        num_batched_functions: params.num_batched_functions,
    };
    let report = proven_security_report(&fri, &air_shape, &instance, &[], &GrindingSites::NONE);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "scope": "interactive round-by-round backend analysis",
            "trace_rows": 1 << TRACE_LOG,
            "merkle_salt_words": MERKLE_SALT_WORDS,
            "query_grinding_bits": QUERY_GRINDING_BITS,
            "poseidon_full_rounds": FULL_ROUNDS,
            "poseidon_partial_rounds": PARTIAL_ROUNDS,
            "stream_leaf_bytes": stream::LEAF_BYTES,
            "stream_query_bytes": stream::QUERY_BYTES,
            "stream_base_bytes": stream::BASE_BYTES,
            "base_prime": Val::ORDER_U32,
            "public_seed_input_bytes": AUTH_DOMAIN.len(),
            "public_seed_digest": NativeHash.hash_slice(AUTH_DOMAIN).iter().map(|v| format!("{v:02x}")).collect::<String>(),
            "initial_capacity": initial_capacity().map(|v| v.as_canonical_u32()),
            "committed_degree_bits": degree_bits,
            "num_constraints": params.num_constraints,
            "maximum_constraint_degree": params.air_max_constraint_degree,
            "quotient_chunks": params.num_quotient_chunks,
            "batched_functions": params.num_batched_functions,
            "extension_size_floor_bits": params.num_modulus_bits,
            "unique_decoding_error_bits": report.udr.security_bits(),
            "list_decoding_error_bits": report.ldr.as_ref().map(|r| r.security_bits()),
            "report": report,
            "quantum_compilation": "native QROM theorem and exact bounds: research/security/compiler.txt and security-evaluation.json"
        }))
        .unwrap()
    );
}

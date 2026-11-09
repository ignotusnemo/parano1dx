use parano1dx_vault_auth::*;
use p3_challenger::{CanObserve, GrindingChallenger};
use p3_uni_stark::{compile_air_metadata, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed_and_compiled};
use std::time::Instant;

fn main() {
    let repetitions: usize = std::env::args().nth(1).unwrap_or("9".into()).parse().unwrap();
    assert!((3..=101).contains(&repetitions));
    let started = Instant::now();
    let (pp, vk) = setup_preprocessed(&preprocessing_config(), &AuthorityAir, TRACE_LOG)
        .unwrap().unwrap();
    let compiled = compile_air_metadata(&config([0; 32]), &AuthorityAir, TRACE_LOG);
    let setup_ms = started.elapsed().as_secs_f64() * 1000.;
    let secret = derive_authority_secret(&[0x42; 32], NETWORK, 0);
    let mut samples = Vec::new();
    for i in 0..repetitions + 2 {
        let request = sha256(&(i as u64).to_le_bytes());
        let mut seed = [0; 32];
        getrandom::fill(&mut seed).unwrap();
        let start = Instant::now();
        let (trace, public) = trace(secret, request, seed);
        let trace_ms = start.elapsed().as_secs_f64() * 1000.;
        let cfg = config(seed);
        let start = Instant::now();
        let proof = prove_with_preprocessed(&cfg, &AuthorityAir, trace, &public, Some(&pp)).unwrap();
        let prove_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        verify_with_preprocessed_and_compiled(&config([0; 32]), &AuthorityAir,
            &proof, &public, Some(&vk), Some(&compiled)).unwrap();
        let verify_ms = start.elapsed().as_secs_f64() * 1000.;
        if i >= 2 {
            samples.push(serde_json::json!({"trace_ms": trace_ms, "prove_ms": prove_ms,
                "verify_ms": verify_ms, "proof_bytes": bincode::serialized_size(&proof).unwrap()}));
        }
    }
    let mut grinding = Vec::new();
    for bits in [8, 12, 16] {
        let mut times = Vec::new();
        for i in 0..11u64 {
            let mut c = Challenger::new(p3_challenger::HashChallenger::new(
                [PARAM_DOMAIN,&[0u8;32]].concat(), NativeHash));
            c.observe(Val::new(i as u32));
            let mut check = c.clone();
            let start = Instant::now();
            let witness = c.grind(bits);
            times.push(start.elapsed().as_secs_f64() * 1000.);
            assert!(check.check_witness(bits, witness));
        }
        grinding.push(serde_json::json!({"bits": bits, "samples_ms": times}));
    }
    let mut proving: Vec<f64> = samples.iter().map(|s| s["prove_ms"].as_f64().unwrap()).collect();
    proving.sort_by(f64::total_cmp);
    let output = serde_json::json!({"parameter_domain": String::from_utf8_lossy(PARAM_DOMAIN),
        "warmup_proofs": 2, "measured_proofs": repetitions, "setup_ms": setup_ms,
        "proving_median_ms": proving[repetitions / 2], "samples": samples,
        "grinding": grinding,
        "scope": "Local host CPU measurements. Preprocessing and trace construction are recorded separately."});
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

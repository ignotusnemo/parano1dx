use std::sync::{Arc, Mutex};

use p3_challenger::{CanObserve, CanSample, HashChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_symmetric::CryptographicHasher;
use parano1dx_vault_auth::{NativeHash, PARAM_DOMAIN, QUERY_GRINDING_BITS, Val};
use serde_json::{Value, json};

#[derive(Default)]
struct Record {
    phase: String,
    previous: Option<[u8; 64]>,
    calls: Vec<Value>,
    rejected_words: usize,
}

#[derive(Clone)]
struct AuditHash(Arc<Mutex<Record>>);

impl CryptographicHasher<u8, [u8; 64]> for AuditHash {
    fn hash_iter<I: IntoIterator<Item = u8>>(&self, input: I) -> [u8; 64] {
        self.hash_slice(&input.into_iter().collect::<Vec<_>>())
    }

    fn hash_slice(&self, input: &[u8]) -> [u8; 64] {
        let output = NativeHash.hash_slice(input);
        let mut record = self.0.lock().unwrap();
        let parent = record.previous.map(|p| input.starts_with(&p));
        assert!(parent.unwrap_or(input.starts_with(PARAM_DOMAIN)));
        let phase = record.phase.clone();
        let continuation = record.previous.is_some() && input.len() == 64;
        record.calls.push(json!({
            "phase": phase,
            "input_bytes": input.len(),
            "carries_full_previous_digest": parent,
            "squeeze_continuation": continuation,
        }));
        record.previous = Some(output);
        output
    }
}

type Challenger = HashChallenger<u8, AuditHash, 64>;

fn hex(value: &Value) -> Vec<u8> {
    let s = value.as_str().unwrap();
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn words(values: &Value) -> Vec<u8> {
    values
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| u32::try_from(v.as_u64().unwrap()).unwrap().to_le_bytes())
        .collect()
}

fn cap(value: &Value) -> Vec<u8> {
    let roots = value["cap"].as_array().unwrap();
    assert_eq!(roots.len(), 1);
    roots[0]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v.as_u64().unwrap().to_le_bytes())
        .collect()
}

fn word(c: &mut Challenger) -> u32 {
    u32::from_le_bytes(c.sample_array())
}

fn extension(c: &mut Challenger, state: &Arc<Mutex<Record>>, phase: &str) -> Vec<u32> {
    state.lock().unwrap().phase = phase.to_owned();
    (0..8)
        .map(|_| {
            loop {
                let v = word(c) & 0x7fff_ffff;
                if v < Val::ORDER_U32 {
                    break Val::from_u32(v).to_unique_u32();
                }
                state.lock().unwrap().rejected_words += 1;
            }
        })
        .collect()
}

fn main() {
    let path = std::env::args().nth(1).expect("evm-export.json path");
    let bytes = std::fs::read(&path).unwrap();
    let data: Value = serde_json::from_slice(&bytes).unwrap();
    let state = Arc::new(Mutex::new(Record::default()));
    let mut c = Challenger::new(PARAM_DOMAIN.to_vec(), AuditHash(state.clone()));
    let commitments = &data["proof"]["commitments"];
    c.observe_slice(&hex(&data["seeds"]["stark"]));
    c.observe_slice(&cap(&commitments["trace"]));
    c.observe_slice(&hex(&data["preprocessed_cap"]));
    c.observe_slice(&words(&data["public_raw"]));
    assert_eq!(
        json!(extension(&mut c, &state, "air-composition")),
        data["transcript"]["alpha"]
    );
    c.observe_slice(&cap(&commitments["quotient_chunks"]));
    c.observe_slice(&cap(&commitments["random"]));
    assert_eq!(
        json!(extension(&mut c, &state, "out-of-domain")),
        data["transcript"]["zeta"]
    );
    c.observe_slice(&hex(&data["seeds"]["pcs"]));
    for batch in data["claims_raw"].as_array().unwrap() {
        for matrix in batch.as_array().unwrap() {
            for point in matrix.as_array().unwrap() {
                for value in point.as_array().unwrap() {
                    c.observe_slice(&words(value));
                }
            }
        }
    }
    assert_eq!(
        json!(extension(&mut c, &state, "opening-batch")),
        data["transcript"]["pcs_alpha"]
    );
    c.observe_slice(&hex(&data["seeds"]["fri"]));
    let fri = &data["proof"]["opening_proof"][1];
    for (i, root) in fri["commit_phase_commits"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        c.observe_slice(&cap(root));
        assert_eq!(
            json!(extension(&mut c, &state, &format!("fri-fold-{i}"))),
            data["transcript"]["betas"][i]
        );
    }
    for coefficient in fri["final_poly"].as_array().unwrap() {
        c.observe_slice(&words(&coefficient["value"]));
    }
    state.lock().unwrap().phase = "query-seal".to_owned();
    let _: u8 = c.sample();
    c.observe_slice(&(u32::try_from(data["query_pow_witness_raw"].as_u64().unwrap()).unwrap()).to_le_bytes());
    state.lock().unwrap().phase = "query-vector".to_owned();
    assert_eq!(word(&mut c)&((1<<QUERY_GRINDING_BITS)-1),0);
    let indices: Vec<_> = (0..64).map(|_| word(&mut c) & 4095).collect();
    assert_eq!(json!(indices), data["transcript"]["indices"]);
    let r = state.lock().unwrap();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "scope": "native transcript replay against exported reference challenges",
            "fixture_sha256": parano1dx_vault_auth::sha256(&bytes).iter()
                .map(|x| format!("{x:02x}")).collect::<String>(),
            "all_challenges_match": true,
            "hash_calls": r.calls,
            "rejected_field_words": r.rejected_words,
            "query_count": indices.len(),
            "query_hash_blocks": r.calls.iter().filter(|v| v["phase"] == "query-vector").count(),
            "compilation_interface": "full-digest chaining with buffered multi-block squeezing",
        }))
        .unwrap()
    );
}

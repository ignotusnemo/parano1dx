use parano1dx_vault_auth::*;
use p3_field::{PrimeCharacteristicRing,PrimeField32};
use p3_uni_stark::{setup_preprocessed,prove_with_preprocessed,verify_with_preprocessed,
    compile_air_metadata,verify_with_preprocessed_and_compiled,verify_with_checks,VerificationChecks};
use std::time::Instant;
mod export;

fn main() {
    if std::env::args().nth(1).as_deref()==Some("--check-stream") {
        let root=std::path::PathBuf::from(std::env::args().nth(2).expect("result directory"));
        let metadata:serde_json::Value=serde_json::from_slice(&std::fs::read(root.join("native-proof.json")).unwrap()).unwrap();
        let request=core::array::from_fn(|i|metadata["request_id"][i].as_u64().unwrap() as u8);
        let commitment=core::array::from_fn(|i|metadata["authority_commitment"][i].as_u64().unwrap() as u8);
        let context=core::array::from_fn(|i|metadata["request_context"][i].as_u64().unwrap() as u8);
        let base=std::fs::read(root.join("stream-base.bin")).unwrap();
        let start=Instant::now();let cache=stream::prepare(&base,request,context,commitment).unwrap();
        let cache_bytes=cache.encode();let cache=stream::QueryCache::read(&cache_bytes).unwrap();
        let mut invalid_grinding_rejected=false;
        for candidate in 0u32..32 {
            let mut altered=base.clone();
            altered[stream::BASE_BYTES-4..].copy_from_slice(&candidate.to_le_bytes());
            if matches!(stream::prepare(&altered,request,context,commitment),Err(stream::StreamError(19))){
                invalid_grinding_rejected=true;break;
            }
        }
        assert!(invalid_grinding_rejected);
        let mut previous=vec![0u8;stream::QUERY_BYTES];
        for i in 0..64 {
            let query=std::fs::read(root.join(format!("stream-query-{i:02}.bin"))).unwrap();
            let delta=std::fs::read(root.join(format!("stream-delta-{i:02}.bin"))).unwrap();
            assert_eq!(stream::expand_delta(&cache,i,&previous,&delta).unwrap(),query);
            let mut trailing=delta.clone();trailing.push(0);assert!(stream::expand_delta(&cache,i,&previous,&trailing).is_err());
            let mut mask=delta.clone();mask[11]|=0x80;assert!(stream::expand_delta(&cache,i,&previous,&mask).is_err());
            if delta.len()>12 {assert!(stream::expand_delta(&cache,i,&previous,&delta[..delta.len()-1]).is_err());}
            stream::check_query(&cache,i,&query).unwrap();
            let mut bad=query.clone();bad[0]^=1;assert!(stream::check_query(&cache,i,&bad).is_err());
            previous=query;
        }
        let mut bad_request=request;bad_request[0]^=1;assert!(stream::prepare(&base,bad_request,context,commitment).is_err());
        for batch_size in 1..=6 {
            let mut cache=stream::QueryCache::read(&cache_bytes).unwrap();
            let mut previous=vec![0u8;stream::QUERY_BYTES];
            for start in (0..64).step_by(batch_size) {
                let count=batch_size.min(64-start);let mut encoded=vec![count as u8];
                for i in start..start+count {
                    let delta=std::fs::read(root.join(format!("stream-delta-{i:02}.bin"))).unwrap();
                    encoded.extend((delta.len() as u16).to_le_bytes());encoded.extend(delta);
                }
                let mut rejected_cache=stream::QueryCache::read(&cache.encode()).unwrap();
                let (last,next)=stream::check_delta_batch(&mut cache,start,&previous,&encoded,batch_size).unwrap();
                assert_eq!(next,start+count);
                assert_eq!(last,std::fs::read(root.join(format!("stream-query-{:02}.bin",next-1))).unwrap());
                let mut invalid=encoded.clone();let n=invalid.len();invalid[n-1]^=1;
                assert!(stream::check_delta_batch(&mut rejected_cache,start,&previous,&invalid,batch_size).is_err());
                previous=last;
            }
        }
        let elapsed=start.elapsed().as_secs_f64()*1000.;
        println!("{}",serde_json::json!({"stream_conjunction_verified":true,"query_count":64,
            "altered_query_rejected":true,"changed_request_rejected":true,"cache_bytes":cache_bytes.len(),
            "invalid_query_grinding_rejected":invalid_grinding_rejected,
            "batch_sizes_checked":[1,2,3,4,5,6],"last_query_corruption_rejected":true,
            "host_check_ms_including_mutations":elapsed}));return;
    }
    let root=std::path::PathBuf::from(std::env::args().nth(1).expect("result directory"));
    std::fs::create_dir_all(&root).unwrap();
    // Local fixtures use a public root. Public-network research can supply a
    // separate owner-only root file. Neither its bytes nor its path is exported.
    let private_root=std::env::var_os("PARANO1DX_RESEARCH_ROOT_FILE");
    let root_secret:[u8;32]=if let Some(path)=&private_root {
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode()&0o077,0,"root file must be owner-only");
        }
        std::fs::read(path).unwrap().try_into().expect("32-byte root file")
    } else {[0x42;32]};
    let network=if let Some(hex)=std::env::args().nth(3) {
        assert_eq!(hex.len(),64);core::array::from_fn(|i|u8::from_str_radix(&hex[2*i..2*i+2],16).unwrap())
    } else {NETWORK};
    let context=if let Some(hex)=std::env::args().nth(4) {assert_eq!(hex.len(),64);core::array::from_fn(|i|u8::from_str_radix(&hex[2*i..2*i+2],16).unwrap())}else{[0;32]};
    let secret=derive_authority_secret(&root_secret,network,0);
    assert_eq!(secret,derive_authority_secret(&root_secret,network,0));
    assert_ne!(secret,derive_authority_secret(&root_secret,network,1));
    let mut other_network=network;other_network[0]^=1;
    assert_ne!(secret,derive_authority_secret(&root_secret,other_network,0));
    let request=if let Some(hex)=std::env::args().nth(2) {
        assert_eq!(hex.len(),64);
        core::array::from_fn(|i|u8::from_str_radix(&hex[2*i..2*i+2],16).unwrap())
    } else {sha256(b"Parano1dX public local withdrawal fixture")};
    let mut seed=[0u8;32];getrandom::fill(&mut seed).unwrap();
    let (t,public)=trace(secret,request,seed);
    let preprocessing=preprocessing_config();
    let (pp,vk)=setup_preprocessed(&preprocessing,&AuthorityAir,TRACE_LOG).unwrap().unwrap();
    let compiled=compile_air_metadata(&preprocessing,&AuthorityAir,TRACE_LOG);
    std::fs::write(root.join("compiled-air.bin"),postcard::to_allocvec(&compiled).unwrap()).unwrap();
    let cfg=config_for_context(seed,context);
    let start=Instant::now();
    let proof=prove_with_preprocessed(&cfg,&AuthorityAir,t,&public,Some(&pp)).unwrap();
    let prove_ms=start.elapsed().as_secs_f64()*1000.0;
    let start=Instant::now();
    p3_fri::checkpoint::start_recording();
    verify_with_preprocessed(&config_for_context([0;32],context),&AuthorityAir,&proof,&public,Some(&vk)).unwrap();
    let native_verify_ms=start.elapsed().as_secs_f64()*1000.0;
    let recorded=p3_fri::checkpoint::take_recorded();
    let hints:Vec<Vec<Vec<Ext>>>=recorded.iter().map(|round|round.iter().map(|bytes|{
        assert_eq!(bytes.len()%core::mem::size_of::<Ext>(),0);
        bytes.chunks_exact(core::mem::size_of::<Ext>()).map(|b|unsafe{b.as_ptr().cast::<Ext>().read_unaligned()}).collect()
    }).collect()).collect();
    let start=Instant::now();
    verify_with_preprocessed_and_compiled(&config_for_context([0;32],context),&AuthorityAir,&proof,&public,Some(&vk),Some(&compiled)).unwrap();
    let verify_ms=start.elapsed().as_secs_f64()*1000.0;
    let mut bytes=encode_proof(&proof,&hints);
    export::write(context,&root,&proof,&public,&hints,&vk,&compiled);
    {
        let decoded=decode_proof(&mut bytes).unwrap();
        assert_eq!(bincode::serialize(&proof).unwrap(),bincode::serialize(&*decoded).unwrap());
        verify_with_preprocessed(&config_for_context([0;32],context),&AuthorityAir,&decoded,&public,Some(&vk)).unwrap();
    }
    // The staged verifier must accept the same complete conjunction as the
    // strict verifier. The wallet never signs a separate spending key.
    let rows=recorded.clone();
    let stages=1+proof.opening_proof.1.input_openings.len()+hints.len()+NUM_QUERIES;
    for stage in 0..stages {
        let batches=proof.opening_proof.1.input_openings.len();let rounds=hints.len();
        let(mode,checks)=if stage==0 {(4u64<<56,VerificationChecks::OuterOnly)}
            else if stage<=batches {((1u64<<56)|(stage-1) as u64,VerificationChecks::OpeningOnly)}
            else if stage<=batches+rounds {((2u64<<56)|(stage-1-batches) as u64,VerificationChecks::OpeningOnly)}
            else {((3u64<<56)|(stage-1-batches-rounds) as u64,VerificationChecks::OpeningOnly)};
        p3_fri::checkpoint::set_native_stage(mode,rows.clone());
        verify_with_checks(&config_for_context([0;32],context),&AuthorityAir,&proof,&public,Some(&vk),Some(&compiled),checks).unwrap();
    }
    p3_fri::checkpoint::set_native_stage(0,Vec::new());
    let mut altered:Proof=bincode::deserialize(&bincode::serialize(&proof).unwrap()).unwrap();
    altered.opening_proof.1.input_openings[0].opened_values[0][0][0]+=Val::ONE;
    assert!(verify_with_preprocessed_and_compiled(&config_for_context([0;32],context),&AuthorityAir,&altered,&public,Some(&vk),Some(&compiled)).is_err());
    let pack=|p:&Proof,h:&[Vec<Vec<Ext>>]| {
        let mut out=Vec::new();for v in &public[..OUTPUTS] {out.extend(v.as_canonical_u32().to_le_bytes());}
        out.extend(encode_proof(p,h));out
    };
    std::fs::write(root.join("altered-opening-capsule.bin"),pack(&altered,&hints)).unwrap();
    let mut changed_hints=hints.clone();changed_hints[0][0][0]+=Ext::ONE;
    std::fs::write(root.join("altered-hints-capsule.bin"),pack(&proof,&changed_hints)).unwrap();
    std::fs::write(root.join("proof.bin"),&bytes).unwrap();
    let mut capsule=Vec::new();
    for v in &public[..OUTPUTS] {capsule.extend(v.as_canonical_u32().to_le_bytes());}
    capsule.extend(&bytes);std::fs::write(root.join("capsule.bin"),&capsule).unwrap();
    std::fs::write(root.join("preprocessed-cap.bin"),postcard::to_allocvec(&vk.commitment).unwrap()).unwrap();
    let out=serde_json::json!({"honest_proof_verified":true,"checkpoint_conjunction_verified":true,
        "altered_opening_rejected":true,"root_recovery_and_network_index_separation":true,"proof_bytes":bytes.len(),
        "prove_ms":prove_ms,"native_verify_ms":native_verify_ms,"compiled_verify_ms":verify_ms,
        "authority_commitment":authority_commitment(&public[..OUTPUTS]),
        "network_domain":network,"vault_index":0,"root_source":if private_root.is_some(){"private research file"}else{"public local fixture"},
        "outputs":public[..OUTPUTS].iter().map(|x|x.as_canonical_u32()).collect::<Vec<_>>(),
        "request_context":context,"request_id":request,"parameter_id":parameter_id(&postcard::to_allocvec(&vk.commitment).unwrap()),
        "preprocessed_width":vk.width,"degree_bits":vk.degree_bits,
        "trace_rows":TRACE_ROWS,"trace_columns":MAIN_WIDTH,"FRI_queries":NUM_QUERIES,
        "input_batches":proof.opening_proof.1.input_openings.len(),"fri_rounds":hints.len(),
        "fri_arities":hints.iter().map(|r|r[0].len()).collect::<Vec<_>>(),
        "FRI_blowup":1<<LOG_BLOWUP,"challenge_extension_degree":8,
        "merkle_salt_words":MERKLE_SALT_WORDS,"query_grinding_bits":QUERY_GRINDING_BITS,
        "poseidon_full_rounds":FULL_ROUNDS,"poseidon_partial_rounds":PARTIAL_ROUNDS,
        "stream_base_bytes":stream::BASE_BYTES,"stream_query_bytes":stream::QUERY_BYTES,
        "hash":"SHA-256 || Keccak-256","zero_knowledge":"HidingFriPcs, hiding Merkle commitments and uni-STARK randomization enabled"});
    std::fs::write(root.join("native-proof.json"),serde_json::to_string_pretty(&out).unwrap()+"\n").unwrap();
    println!("{}",serde_json::json!({"verified":true,"proof_bytes":bytes.len(),"prove_ms":prove_ms,"verify_ms":verify_ms}));
}

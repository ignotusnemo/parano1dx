use parano1dx_vault_auth::*;
use p3_challenger::CanObserve;
use p3_field::{BasedVectorSpace,PrimeCharacteristicRing,PrimeField32,TwoAdicField,Field};
use p3_fri::{PcsShape,FriShape,PcsProverTranscript,ProverTranscript};
use p3_uni_stark::{StarkShape,StarkVerifierTranscript,CompiledAirMetadata};
use p3_symmetric::MerkleCap;
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_commit::PolynomialSpace;

#[derive(Default)] struct Recorder(Vec<Val>);
impl CanObserve<Val> for Recorder {fn observe(&mut self,x:Val){self.0.push(x)}}
fn ext(x:Ext)->Vec<u32>{<Ext as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&x).iter().map(|x|x.to_unique_u32()).collect()}
fn fields(xs:&[Val])->Vec<u32>{xs.iter().map(|x|x.to_unique_u32()).collect()}
fn seed_hex(xs:&[Val])->String {xs.iter().flat_map(|x|x.to_unique_u32().to_le_bytes()).map(|x|format!("{x:02x}")).collect()}
pub fn write(context:[u8;32],root:&std::path::Path,p:&Proof,public:&[Val],hints:&[Vec<Vec<Ext>>],vk:&Vk,compiled:&CompiledAirMetadata){
    let chunks=p.opened_values.quotient_chunks.len();
    let stark=StarkShape::new::<Val,AuthorityAir>(&AuthorityAir,PRE_WIDTH,TRACE_LOG+1,TRACE_LOG,chunks,true,0);
    let mut sr=Recorder::default();stark.domain_separator::<Val,Ext>().seed(&mut sr);
    let mut claims=vec![vec![vec![p.opened_values.random.as_ref().unwrap().clone()]],
        vec![vec![p.opened_values.trace_local.clone(),p.opened_values.trace_next.as_ref().unwrap().clone()]],
        p.opened_values.quotient_chunks.iter().map(|x|vec![x.clone()]).collect(),
        vec![vec![p.opened_values.preprocessed.as_ref().unwrap().local.clone()]]];
    for (claim,random) in claims.iter_mut().zip(&p.opening_proof.0){
        for (matrix,random_matrix) in claim.iter_mut().zip(random){for (point,random_point) in matrix.iter_mut().zip(random_matrix){point.extend(random_point)}}
    }
    let cfg=config([0;32]);
    let params=p3_fri::FriParameters{log_blowup:LOG_BLOWUP,log_final_poly_len:0,max_log_arity:2,
        num_queries:NUM_QUERIES,batch_proof_of_work_bits:0,commit_proof_of_work_bits:0,query_proof_of_work_bits:QUERY_GRINDING_BITS,
        mmcs:()};
    let pcs=PcsShape::from_opened_values(&params,&claims);let mut pr=Recorder::default();
    pcs.domain_separator::<Val,Ext>().seed(&mut pr);
    let fri=FriShape::with_schedule(&params,hints.iter().map(|r|r[0].len().ilog2() as usize).collect(),12);let mut fr=Recorder::default();
    fri.domain_separator::<Val,Ext>().seed(&mut fr);
    let mut initial=PARAM_DOMAIN.to_vec();initial.extend(context);
    let mut challenger=Challenger::new(p3_challenger::HashChallenger::new(initial,NativeHash));
    let mut st=StarkVerifierTranscript::<_,Val,Ext>::new(&mut challenger,stark);
    let alpha=st.constraint_phase(p.commitments.trace.clone(),Some(vk.commitment.clone()),public).unwrap();
    let zeta=st.ood_phase(p.commitments.quotient_chunks.clone(),p.commitments.random.clone(),Val::ZERO).unwrap();
    let mut pa=Ext::ZERO;let mut betas=Vec::new();let mut indices=Vec::new();
    st.delegate(|challenger|{
        let mut pt=PcsProverTranscript::<_,Val,Ext>::new(challenger,pcs);
        pt.claimed_openings(&claims);pa=pt.batch_phase().0;
        pt.delegate(|challenger|{
            let mut ft=ProverTranscript::<_,Val,Ext>::new(challenger,fri);
            for c in &p.opening_proof.1.commit_phase_commits {betas.push(ft.commit_round(c.clone()).0)}
            let (positions,witness)=ft.query_phase(&p.opening_proof.1.final_poly);
            assert_eq!(witness,Some(p.opening_proof.1.query_pow_witness));
            indices=positions;ft.finish();
        });pt.finish();
    });st.finish();
    let matrix=|internal:bool|->Vec<Vec<u32>>{(0..WIDTH).map(|i|{let mut v=[Val::ZERO;WIDTH];v[i]=Val::ONE;
        if internal {GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(&mut v)}
        else {GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut v)};fields(&v)
    }).collect()};
    let cap=|c:&MerkleCap<Val,[u64;8]>|->String {c.roots()[0].iter().flat_map(|x|x.to_le_bytes()).map(|x|format!("{x:02x}")).collect()};
    let raw_hints:Vec<Vec<Vec<Vec<u32>>>>=hints.iter().map(|r|r.iter().map(|q|q.iter().map(|&x|ext(x)).collect()).collect()).collect();
    let td=p3_field::coset::TwoAdicMultiplicativeCoset::new(Val::ONE,TRACE_LOG+1).unwrap();
    let qd=td.create_disjoint_domain(1<<(TRACE_LOG+chunks.ilog2() as usize));
    let qcs=qd.split_domains(chunks);
    let denominators:Vec<_>=qcs.iter().enumerate().map(|(i,d)|qcs.iter().enumerate().filter(|(j,_)|i!=*j)
        .map(|(_,other)|other.vanishing_poly_at_point(d.first_point())).product::<Val>().inverse().to_unique_u32()).collect();
    let query_inverses:Vec<_>=indices.iter().map(|&index|{
        let reversed=(index as u32).reverse_bits()>>20;
        let point=Val::GENERATOR*Val::two_adic_generator(12).exp_u64(reversed as u64);
        [ext((zeta-Ext::from(point)).inverse()),ext((zeta*Val::two_adic_generator(6)-Ext::from(point)).inverse())]
    }).collect();
    let outer_inverses=[ext((zeta-Ext::ONE).inverse()),
        ext((zeta-Ext::from(Val::two_adic_generator(7).exp_u64(127))).inverse()),
        ext((zeta.exp_power_of_2(7)-Ext::ONE).inverse())];
    let out=serde_json::json!({"proof":p,"claims_raw":claims.iter().map(|r|r.iter().map(|m|m.iter().map(|pt|pt.iter().map(|&x|ext(x)).collect::<Vec<_>>()).collect::<Vec<_>>()).collect::<Vec<_>>()).collect::<Vec<_>>(),
        "query_inverse_hints_raw":query_inverses,"outer_inverse_hints_raw":outer_inverses,
        "hints_raw":raw_hints,"seeds":{"stark":seed_hex(&sr.0),"pcs":seed_hex(&pr.0),"fri":seed_hex(&fr.0)},
        "public_raw":fields(public),"preprocessed_cap":cap(&vk.commitment),"chunks":chunks,
        "generators_raw":(0..=12).map(|i|Val::two_adic_generator(i).to_unique_u32()).collect::<Vec<_>>(),
        "field_generator_raw":Val::GENERATOR.to_unique_u32(),"capacity_raw":fields(&initial_capacity()),
        "external_matrix_columns_raw":matrix(false),"internal_matrix_columns_raw":matrix(true),
        "transcript":{"alpha":ext(alpha),"zeta":ext(zeta),"pcs_alpha":ext(pa),"betas":betas.into_iter().map(ext).collect::<Vec<_>>(),"indices":indices},
        "request_context":context,"profile":{"parameter_domain":core::str::from_utf8(PARAM_DOMAIN).unwrap(),
            "authority_domain":core::str::from_utf8(AUTH_DOMAIN).unwrap(),
            "merkle_salt_words":MERKLE_SALT_WORDS,"query_grinding_bits":QUERY_GRINDING_BITS,
            "full_rounds":FULL_ROUNDS,"partial_rounds":PARTIAL_ROUNDS},
        "query_pow_witness_raw":p.opening_proof.1.query_pow_witness.to_unique_u32(),
        "quotient_shifts_raw":qcs.iter().map(|d|d.first_point().to_unique_u32()).collect::<Vec<_>>(),
        "quotient_denominator_inverses_raw":denominators,"quotient_chunk_size":qcs[0].size(),
        "compiled_air":compiled});
    std::fs::write(root.join("evm-export.json"),serde_json::to_string(&out).unwrap()+"\n").unwrap();
    let _=cfg;
}

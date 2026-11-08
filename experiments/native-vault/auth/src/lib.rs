#![no_std]
extern crate alloc;

pub mod stream;

use alloc::{boxed::Box,vec,vec::Vec};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs};
use p3_koala_bear::{KoalaBear, GenericPoseidon2LinearLayersKoalaBear,
    KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL as RC_FIRST,
    KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL as RC_LAST,
    KOALABEAR_POSEIDON2_RC_24_INTERNAL as RC_PARTIAL};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_symmetric::{CryptographicHasher,CompressionFunction,PseudoCompressionFunction};
use p3_uni_stark::{StarkConfig, PreprocessedVerifierKey};
use rand::{SeedableRng, rngs::StdRng};

pub type Val = KoalaBear;
pub type Ext = BinomialExtensionField<Val, 8>;
pub const TRACE_LOG: usize = 8;
pub const TRACE_ROWS: usize = 1 << TRACE_LOG;
pub const WIDTH: usize = 24;
pub const SECRET_WORDS: usize = 14;
pub const CAPACITY_WORDS: usize = WIDTH - SECRET_WORDS;
pub const OUTPUTS: usize = 12;
pub const REQUEST_LIMBS: usize = 16;
pub const MAIN_WIDTH: usize = WIDTH + REQUEST_LIMBS;
pub const PRE_WIDTH: usize = WIDTH + 3;
pub const NUM_QUERIES: usize = 64;
pub const LOG_BLOWUP: usize = 3;
pub const NETWORK: [u8;32] = *include_bytes!(concat!(env!("OUT_DIR"),"/network-domain.bin"));
pub const AUTH_DOMAIN: &[u8] = b"Parano1dX/v1/authority/koalabear24";
pub const PARAM_DOMAIN: &[u8] = b"Parano1dX/v1/zkfri-kb24-ext8-q64-b8-a4-salt10-hybrid512";

/// Independent SHA-256 and Keccak-256 outputs form the prototype's 64-byte
/// transcript and Merkle hash. Both operations have native host-chain support.
#[derive(Clone, Copy, Debug)]
pub struct NativeHash;

#[cfg(target_os = "solana")]
#[repr(C)]
#[derive(Clone,Copy)]
struct ByteSlice { addr: *const u8, len: u64 }
#[cfg(target_os = "solana")]
unsafe extern "C" {
    fn sol_sha256(slices: *const ByteSlice, count: u64, output: *mut u8) -> u64;
    fn sol_keccak256(slices: *const ByteSlice, count: u64, output: *mut u8) -> u64;
    fn sol_log_64_(a:u64,b:u64,c:u64,d:u64,e:u64);
    fn sol_log_compute_units_();
}

fn vm_mark(stage:u64) {
    #[cfg(target_os="solana")]
    unsafe {sol_log_64_(stage,0,0,0,0);sol_log_compute_units_();}
    #[cfg(not(target_os="solana"))]
    let _=stage;
}

pub fn sha256(input: &[u8]) -> [u8;32] {
    #[cfg(not(target_os="solana"))]
    { use sha2::Digest; sha2::Sha256::digest(input).into() }
    #[cfg(target_os="solana")]
    { let mut out=[0u8;32]; let s=[ByteSlice{addr:input.as_ptr(),len:input.len() as u64}];
      let code=unsafe{sol_sha256(s.as_ptr(),1,out.as_mut_ptr())}; assert_eq!(code,0); out }
}
pub fn keccak256(input: &[u8]) -> [u8;32] {
    #[cfg(not(target_os="solana"))]
    { use sha3::Digest; sha3::Keccak256::digest(input).into() }
    #[cfg(target_os="solana")]
    { let mut out=[0u8;32]; let s=[ByteSlice{addr:input.as_ptr(),len:input.len() as u64}];
      let code=unsafe{sol_keccak256(s.as_ptr(),1,out.as_mut_ptr())}; assert_eq!(code,0); out }
}
impl CryptographicHasher<u8,[u8;64]> for NativeHash {
    fn hash_slice(&self,input:&[u8])->[u8;64] {hybrid_slices(&[input])}
    fn hash_iter<I:IntoIterator<Item=u8>>(&self, input:I)->[u8;64] {
        let bytes:Vec<u8>=input.into_iter().collect();
        hybrid_slices(&[&bytes])
    }
    fn hash_iter_slices<'a,I:IntoIterator<Item=&'a[u8]>>(&self,input:I)->[u8;64] {
        let slices:Vec<&[u8]>=input.into_iter().collect();hybrid_slices(&slices)
    }
}

fn hybrid_slices(slices:&[&[u8]])->[u8;64] {
    let mut out=[0u8;64];
    #[cfg(not(target_os="solana"))]
    {
        use sha2::Digest;
        let mut a=sha2::Sha256::new();let mut b=sha3::Keccak256::new();
        for s in slices {a.update(s);b.update(s)}
        out[..32].copy_from_slice(&a.finalize());out[32..].copy_from_slice(&b.finalize());
    }
    #[cfg(target_os="solana")]
    {
        assert!(slices.len()<=64);
        let mut descriptors=[core::mem::MaybeUninit::<ByteSlice>::uninit();64];
        for (d,s) in descriptors.iter_mut().zip(slices) {d.write(ByteSlice{addr:s.as_ptr(),len:s.len() as u64});}
        unsafe {
            assert_eq!(sol_sha256(descriptors.as_ptr().cast::<ByteSlice>(),slices.len() as u64,out.as_mut_ptr()),0);
            assert_eq!(sol_keccak256(descriptors.as_ptr().cast::<ByteSlice>(),slices.len() as u64,out.as_mut_ptr().add(32)),0);
        }
    }out
}

fn digest_words(bytes:[u8;64])->[u64;8] {
    core::array::from_fn(|i|u64::from_le_bytes(bytes[i*8..i*8+8].try_into().unwrap()))
}
#[derive(Clone,Copy,Debug)]
pub struct FieldHash;
impl CryptographicHasher<Val,[u64;8]> for FieldHash {
    fn hash_slice(&self,input:&[Val])->[u64;8] {
        let bytes=unsafe{core::slice::from_raw_parts(input.as_ptr().cast::<u8>(),core::mem::size_of_val(input))};
        digest_words(hybrid_slices(&[b"Parano1dX/leaf",bytes]))
    }
    fn hash_iter<I:IntoIterator<Item=Val>>(&self,input:I)->[u64;8] {
        let mut data=[0u32;256];let mut n=0;
        for x in input {assert!(n<data.len());data[n]=x.to_unique_u32();n+=1;}
        let bytes=unsafe{core::slice::from_raw_parts(data.as_ptr().cast::<u8>(),n*4)};
        digest_words(hybrid_slices(&[b"Parano1dX/leaf",bytes]))
    }
    fn hash_iter_slices<'a,I:IntoIterator<Item=&'a[Val]>>(&self,input:I)->[u64;8] {
        let mut slices:[&[u8];64]=[&[];64];slices[0]=b"Parano1dX/leaf";let mut n=1;
        for s in input {assert!(n<slices.len());
            slices[n]=unsafe{core::slice::from_raw_parts(s.as_ptr().cast::<u8>(),core::mem::size_of_val(s))};n+=1;
        }
        digest_words(hybrid_slices(&slices[..n]))
    }
}
#[derive(Clone,Copy,Debug)]
pub struct Compress;
impl PseudoCompressionFunction<[u64;8],2> for Compress {
    fn compress(&self,input:[[u64;8];2])->[u64;8] {
        let bytes=unsafe{core::slice::from_raw_parts(input.as_ptr().cast::<u8>(),128)};
        digest_words(hybrid_slices(&[b"Parano1dX/node",bytes]))
    }
}
impl CompressionFunction<[u64;8],2> for Compress {}
pub type ValMmcs = MerkleTreeHidingMmcs<Val,u64,FieldHash,Compress,StdRng,2,8,10>;
pub type ExtMmcs = ExtensionMmcs<Val,Ext,ValMmcs>;
pub type Challenger = SerializingChallenger32<Val,HashChallenger<u8,NativeHash,64>>;
pub type Pcs = HidingFriPcs<Val,Radix2DitParallel<Val>,ValMmcs,ExtMmcs,StdRng>;
pub type Config = StarkConfig<Pcs,Ext,Challenger>;
pub type Proof = p3_uni_stark::Proof<Config>;
pub type Vk = PreprocessedVerifierKey<Config>;
pub mod wire;
pub use wire::{encode_proof,decode_proof};

/// Proving callers supply an unpredictable 256-bit seed for every proof.
/// Verification consumes no masking randomness.
pub fn config(seed:[u8;32])->Config {
    let mut salt_seed=seed;salt_seed[0]^=0xa7;
    let mmcs=ValMmcs::new(FieldHash,Compress,0,StdRng::from_seed(salt_seed));
    let ext_mmcs=ExtMmcs::new(mmcs.clone());
    let params=FriParameters {log_blowup:LOG_BLOWUP,log_final_poly_len:0,max_log_arity:2,
        num_queries:NUM_QUERIES,batch_proof_of_work_bits:0,commit_proof_of_work_bits:0,
        query_proof_of_work_bits:0,mmcs:ext_mmcs};
    let pcs=Pcs::new(Radix2DitParallel::default(),mmcs,params,8,StdRng::from_seed(seed));
    Config::new(pcs,Challenger::new(HashChallenger::new(PARAM_DOMAIN.to_vec(),NativeHash)))
}

#[derive(Clone,Copy)]
pub struct AuthorityAir;

fn round_params(row:usize)->([Val;WIDTH],bool,bool,bool) {
    let mut rc=[Val::ZERO;WIDTH];
    if row==0 {return(rc,true,false,false)}
    if (1..5).contains(&row) {rc=RC_FIRST[row-1];return(rc,false,true,false)}
    if (5..28).contains(&row) {rc[0]=RC_PARTIAL[row-5];return(rc,false,false,true)}
    if (28..32).contains(&row) {rc=RC_LAST[row-28];return(rc,false,true,false)}
    (rc,false,false,false)
}

pub fn initial_capacity()->[Val;CAPACITY_WORDS] {
    let d=NativeHash.hash_iter(AUTH_DOMAIN.iter().copied());
    core::array::from_fn(|i|Val::from_u32(u32::from_le_bytes(d[i*4..i*4+4].try_into().unwrap())))
}

impl BaseAir<Val> for AuthorityAir {
    fn width(&self)->usize {MAIN_WIDTH}
    fn num_public_values(&self)->usize {OUTPUTS+REQUEST_LIMBS}
    fn preprocessed_width(&self)->usize {PRE_WIDTH}
    fn preprocessed_next_row_columns(&self)->Vec<usize> {vec![]}
    fn main_next_row_columns(&self)->Vec<usize> {(0..WIDTH).collect()}
    fn preprocessed_trace(&self)->Option<RowMajorMatrix<Val>> {
        let mut out=Vec::with_capacity(TRACE_ROWS*PRE_WIDTH);
        for row in 0..TRACE_ROWS {
            let (rc,init,full,partial)=round_params(row);
            out.extend(rc);out.extend([Val::from_bool(init),Val::from_bool(full),Val::from_bool(partial)]);
        }
        Some(RowMajorMatrix::new(out,PRE_WIDTH))
    }
}

fn boxed_array<T>(input:impl Iterator<Item=T>)->Box<[T;WIDTH]> {
    input.collect::<Vec<_>>().into_boxed_slice().try_into().ok().unwrap()
}

impl<AB:AirBuilder<F=Val>> Air<AB> for AuthorityAir {
    fn eval(&self,b:&mut AB) {
        vm_mark(10);
        let main=b.main();let local=main.current_slice();let next=main.next_slice();
        let pre=b.preprocessed();let p=pre.current_slice();
        let public=b.public_values().to_vec();
        let state:Vec<AB::Expr>=local[..WIDTH].iter().map(|&x|x.into()).collect();
        let init:AB::Expr=p[WIDTH].into();let full:AB::Expr=p[WIDTH+1].into();
        let partial:AB::Expr=p[WIDTH+2].into();
        let copy=AB::Expr::ONE-init.clone()-full.clone()-partial.clone();
        let mut a=boxed_array(state.iter().cloned());
        GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut *a);
        let mut f=boxed_array((0..WIDTH).map(|i|{
            let x=state[i].clone()+p[i];x.cube()
        }));
        GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut *f);
        let mut part=boxed_array(state.iter().cloned());part[0]=(part[0].clone()+p[0]).cube();
        GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(&mut *part);
        for i in 0..WIDTH {
            let expected=init.clone()*a[i].clone()+full.clone()*f[i].clone()
                +partial.clone()*part[i].clone()+copy.clone()*state[i].clone();
            b.when_transition().assert_eq(next[i],expected);
        }
        for (i,c) in initial_capacity().into_iter().enumerate() {
            b.when_first_row().assert_eq(local[SECRET_WORDS+i],c);
        }
        for i in 0..OUTPUTS {b.when_last_row().assert_eq(local[i],public[i]);}
        for i in 0..REQUEST_LIMBS {b.assert_eq(local[WIDTH+i],public[OUTPUTS+i]);}
        vm_mark(11);
    }
}

pub fn trace(secret:[Val;SECRET_WORDS],request_id:[u8;32])->(RowMajorMatrix<Val>,Vec<Val>) {
    let request=core::array::from_fn::<_,REQUEST_LIMBS,_>(|i|Val::from_u16(u16::from_le_bytes([request_id[2*i],request_id[2*i+1]])));
    let mut state=[Val::ZERO;WIDTH];state[..SECRET_WORDS].copy_from_slice(&secret);
    state[SECRET_WORDS..].copy_from_slice(&initial_capacity());
    let mut values=Vec::with_capacity(TRACE_ROWS*MAIN_WIDTH);
    for row in 0..TRACE_ROWS {
        values.extend(state);values.extend(request);
        let (rc,init,full,partial)=round_params(row);
        if init {GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut state);}
        else if full {
            for i in 0..WIDTH {state[i]=(state[i]+rc[i]).cube();}
            GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut state);
        } else if partial {
            state[0]=(state[0]+rc[0]).cube();
            GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(&mut state);
        }
    }
    let mut public=state[..OUTPUTS].to_vec();public.extend(request);
    (RowMajorMatrix::new(values,MAIN_WIDTH),public)
}

pub fn authority_commitment(outputs:&[Val])->[u8;32] {
    assert_eq!(outputs.len(),OUTPUTS);
    let mut bytes=AUTH_DOMAIN.to_vec();
    for x in outputs {bytes.extend(x.as_canonical_u32().to_le_bytes());}
    sha256(&bytes)
}

/// Derive an independent external authority from a 256-bit Parano1d secret.
/// Network identity and account index are part of the derivation domain.
#[cfg(not(target_os="solana"))]
pub fn derive_authority_secret(parano1d_secret:&[u8;32],network:[u8;32],index:u64)->[Val;SECRET_WORDS] {
    let kdf=hkdf::Hkdf::<sha2::Sha256>::new(Some(b"Parano1dX/root-derivation/v1"),parano1d_secret);
    let mut info=AUTH_DOMAIN.to_vec();info.extend(network);info.extend(index.to_le_bytes());
    let mut bytes=[0u8;SECRET_WORDS*4];kdf.expand(&info,&mut bytes).unwrap();
    core::array::from_fn(|i|Val::from_u32(u32::from_le_bytes(bytes[i*4..i*4+4].try_into().unwrap())))
}

pub fn public_values(outputs:&[Val],request_id:[u8;32])->Vec<Val> {
    let mut out=outputs.to_vec();
    for v in request_id.chunks_exact(2) {out.push(Val::from_u16(u16::from_le_bytes([v[0],v[1]])));}
    out
}

pub fn parameter_id(preprocessed_cap:&[u8])->[u8;32] {
    let mut out=PARAM_DOMAIN.to_vec();out.extend(preprocessed_cap);sha256(&out)
}
pub fn withdrawal_id(program:[u8;32],vault:[u8;32],recipient:[u8;32],nonce:u64,
    amount:u64,expires:u64,parameters:[u8;32])->[u8;32] {
    let mut out=b"Parano1dX/v1/withdraw/SOL".to_vec();
    out.extend(NETWORK);out.extend(program);out.extend(vault);out.extend(parameters);
    out.extend(nonce.to_le_bytes());out.extend(recipient);out.extend(amount.to_le_bytes());
    out.extend(expires.to_le_bytes());
    out.extend([0u8;32]);out.extend(0u64.to_le_bytes());
    sha256(&out)
}

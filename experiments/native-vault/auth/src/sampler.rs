use alloc::{vec::Vec,vec};
use p3_challenger::{ByteGrindingChallenger,CanObserve,CanSample,CanSampleBits,FieldChallenger,GrindingChallenger,HashChallenger};
use p3_field::{BasedVectorSpace,PrimeCharacteristicRing,PrimeField32};
use p3_symmetric::{Hash,MerkleCap};
use crate::{Val,NativeHash};

/// Fixed-width unsigned arithmetic. Every intermediate is below 2^512.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Wide(pub [u32;16]);
impl Wide {
    pub const ZERO:Self=Self([0;16]);
    pub fn from_bytes(b:[u8;64])->Self {Self(core::array::from_fn(|i|u32::from_le_bytes(b[4*i..4*i+4].try_into().unwrap())))}
    pub fn greater(&self,b:&Self)->bool {(0..16).rev().find_map(|i|(self.0[i]!=b.0[i]).then_some(self.0[i]>b.0[i])).unwrap_or(false)}
    pub fn subtract(&mut self,b:&Self) {let mut borrow=0u64;for i in 0..16 {let rhs=u64::from(b.0[i])+borrow;let x=u64::from(self.0[i]);self.0[i]=x.wrapping_sub(rhs) as u32;borrow=u64::from(x<rhs);}assert_eq!(borrow,0);}
    fn len(&self)->usize {self.0.iter().rposition(|&x|x!=0).map_or(1,|i|i+1)}
    pub fn add(&mut self,b:&Self) {let mut carry=0u64;let n=self.len().max(b.len());for i in 0..n {let v=u64::from(self.0[i])+u64::from(b.0[i])+carry;self.0[i]=v as u32;carry=v>>32;}if carry!=0 {assert!(n<16);self.0[n]=carry as u32;}}
    pub fn multiply(&mut self,b:u32) {let mut carry=0u64;let n=self.len();for x in &mut self.0[..n] {let v=u64::from(*x)*u64::from(b)+carry;*x=v as u32;carry=v>>32;}if carry!=0 {assert!(n<16);self.0[n]=carry as u32;}}
    pub fn divide(&mut self,b:u32)->u32 {let mut rem=0u64;let n=self.len();for x in self.0[..n].iter_mut().rev() {let v=(rem<<32)|u64::from(*x);*x=(v/u64::from(b)) as u32;rem=v%u64::from(b);}rem as u32}
    pub fn shift_right(&mut self,bits:usize) {assert!(bits<32);if bits==0{return}for i in 0..16 {self.0[i]=(self.0[i]>>bits)|if i+1<16 {self.0[i+1]<<(32-bits)}else{0};}}
    pub fn modulo(mut self,b:Self)->Self {for bit in (0..=(b.0.iter().rev().take_while(|&&x|x==0).count()*32+b.0.iter().rev().find(|&&x|x!=0).unwrap().leading_zeros() as usize)).rev() {let mut shifted=Self::ZERO;let w=bit/32;let r=bit%32;let mut overflow=false;for i in 0..16 {let x=b.0[i];if i+w<16 {shifted.0[i+w]|=x<<r;}else if x!=0 {overflow=true;}if r!=0 {if i+w+1<16 {shifted.0[i+w+1]|=x>>(32-r);}else if x>>(32-r)!=0 {overflow=true;}}}if !overflow&&!shifted.greater(&self) {self.subtract(&shifted);}}self}
}
pub const SUBSETS:Wide=Wide([1841504192,1597270577,3941309731,987750866,2389857321,296068242,2422500686,655362129,3336352709,1306524527,1395718823,3101506600,1627908432,467740239,10263941,0]);

/// Colexicographic unranking of one of the C(4096,64) distinct subsets.
pub fn unrank(mut rank:Wide)->[usize;64] {
    assert!(SUBSETS.greater(&rank));
    let mut out=[0;64];let mut n=4095u32;let mut c=SUBSETS;c.multiply(4032);assert_eq!(c.divide(4096),0);
    for k in (1..=64u32).rev() {
        while c.greater(&rank) {
            if n>=k+1 {let mut trial=c;trial.multiply((n-k)*(n-k-1));assert_eq!(trial.divide(n*(n-1)),0);if trial.greater(&rank) {c=trial;n-=2;continue}}
            c.multiply(n-k);assert_eq!(c.divide(n),0);n-=1;
        }
        out[k as usize-1]=n as usize;rank.subtract(&c);
        if k>1 {c.multiply(k);assert_eq!(c.divide(n),0);n-=1;}
    }
    assert_eq!(rank,Wide::ZERO);out
}
pub fn positions(bytes:[u8;64],grinding_bits:usize)->[usize;64] {let mut r=Wide::from_bytes(bytes);r.shift_right(grinding_bits);unrank(r.modulo(SUBSETS))}

/// Every extension challenge and the complete query subset use one full hash response.
#[derive(Clone,Debug)]
pub struct Challenger {
    inner:HashChallenger<u8,NativeHash,64>,
    field_words:Vec<Val>,
    queries:Vec<usize>,
}
impl Challenger {
    pub fn new(inner:HashChallenger<u8,NativeHash,64>)->Self {Self{inner,field_words:vec![],queries:vec![]}}
    fn observe_bytes(&mut self,b:&[u8]) {self.field_words.clear();self.queries.clear();self.inner.observe_slice(b);}
    fn base(&mut self)->Val {
        if self.field_words.is_empty() {let mut n=Wide::from_bytes(self.inner.sample_array());let mut words=[Val::ZERO;8];for x in &mut words {*x=Val::new(n.divide(Val::ORDER_U32));}self.field_words.extend(words.into_iter().rev());}
        self.field_words.pop().unwrap()
    }
}
impl CanObserve<Val> for Challenger {fn observe(&mut self,v:Val){self.observe_bytes(&v.to_unique_u32().to_le_bytes());}}
impl<const N:usize> CanObserve<Hash<Val,u64,N>> for Challenger {fn observe(&mut self,h:Hash<Val,u64,N>){for w in h {self.observe_bytes(&w.to_le_bytes());}}}
impl<const N:usize> CanObserve<MerkleCap<Val,[u64;N]>> for Challenger {fn observe(&mut self,c:MerkleCap<Val,[u64;N]>){self.observe(&c);}}
impl<const N:usize> CanObserve<&MerkleCap<Val,[u64;N]>> for Challenger {fn observe(&mut self,c:&MerkleCap<Val,[u64;N]>){for h in c.roots(){for w in h {self.observe_bytes(&w.to_le_bytes());}}}}
impl<EF:BasedVectorSpace<Val>> CanSample<EF> for Challenger {fn sample(&mut self)->EF {EF::from_basis_coefficients_fn(|_|self.base())}}
impl CanSampleBits<usize> for Challenger {fn sample_bits(&mut self,bits:usize)->usize {assert_eq!(bits,12);self.queries.pop().expect("query subset is prepared by its positive grind")}}
impl FieldChallenger<Val> for Challenger {}
impl GrindingChallenger for Challenger {
    type Witness=Val;
    fn grind(&mut self,bits:usize)->Val {
        if bits==0{return Val::ZERO}
        let mut squeezed=self.inner.clone();let _:u8=squeezed.sample();
        let mask=(1u32<<bits)-1;
        let i=squeezed.find_witness(u64::from(Val::ORDER_U32),|i|Val::from_u64(i).to_unique_u32().to_le_bytes(),|b:[u8;4]|u32::from_le_bytes(b)&mask==0).expect("a grinding witness exists");
        let w=Val::from_u64(i);assert!(self.check_witness(bits,w));w
    }
    fn check_witness(&mut self,bits:usize,w:Val)->bool {
        if bits==0{return true}
        self.field_words.clear();let _:u8=self.inner.sample();self.observe(w);
        let b:[u8;64]=self.inner.sample_array();
        if u32::from_le_bytes(b[..4].try_into().unwrap())&((1u32<<bits)-1)!=0{return false}
        self.queries=positions(b,bits).into_iter().rev().collect();true
    }
}

/// Verify the bijective subset encoding through its exact colexicographic rank.
pub fn expected_rank(bytes:[u8;64],bits:usize)->Wide {let mut expected=Wide::from_bytes(bytes);expected.shift_right(bits);expected.modulo(SUBSETS)}
pub fn rank_term(n:usize,k:usize)->Wide {
    if n<k{return Wide::ZERO}
    let n=n as u32;let k=(k as u32).min(n-k as u32);let mut term=Wide::ZERO;term.0[0]=1;
    for j in 1..=k {term.multiply(n-k+j);assert_eq!(term.divide(j),0)}term
}
pub fn verify_positions(bytes:[u8;64],bits:usize,positions:&[usize])->bool {
    if positions.len()!=64||positions.iter().any(|&x|x>=4096)||positions.windows(2).any(|p|p[0]>=p[1]) {return false}
    let mut rank=Wide::ZERO;for(i,&n)in positions.iter().enumerate(){rank.add(&rank_term(n,i+1));}rank==expected_rank(bytes,bits)
}

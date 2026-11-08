//! Fixed-profile verifier with a reusable public-witness window.
//!
//! The Fiat-Shamir transcript and ordinary Merkle paths are identical to the
//! independently checked EVM export. Only the transport and retained cache
//! change. The host program protects the cache and contiguous query counter.
use alloc::vec::Vec;
use p3_field::{BasedVectorSpace,Field,PrimeCharacteristicRing,PrimeField32};
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear as Layers;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use crate::{Val,Ext,PARAM_DOMAIN,authority_commitment,initial_capacity,hybrid_slices};
#[path="stream_parameters.rs"]
mod parameters;
use parameters::*;

pub const BASE_BYTES:usize=9232;
pub const QUERY_BYTES:usize=7212;
pub const CACHE_BYTES:usize=9792;
pub const DELTA_HEADER_BYTES:usize=12;
const LEAF_BYTES:[usize;9]=[104,232,832,148,168,168,168,168,104];
const HEIGHTS:[usize;9]=[12,12,12,12,10,8,6,4,3];
#[derive(Debug,Clone,Copy)]
pub struct StreamError(pub u32);
type Result<T>=core::result::Result<T,StreamError>;
fn require(ok:bool,code:u32)->Result<()> {if ok {Ok(())}else{Err(StreamError(code))}}

struct Reader<'a>{data:&'a[u8],at:usize}
impl<'a> Reader<'a> {
    fn take(&mut self,n:usize)->Result<&'a[u8]> {
        let end=self.at.checked_add(n).ok_or(StreamError(1))?;
        let out=self.data.get(self.at..end).ok_or(StreamError(1))?;self.at=end;Ok(out)
    }
    fn val(&mut self)->Result<Val> {
        let v=u32::from_le_bytes(self.take(4)?.try_into().unwrap());
        require(v<Val::ORDER_U32,2)?;
        // Val is repr(transparent) over a reduced Montgomery u32. Every
        // integer is validated before constructing this initialized value.
        Ok(unsafe{core::mem::transmute::<u32,Val>(v)})
    }
    fn ext(&mut self)->Result<Ext> {
        let mut x=[Val::ZERO;8];for v in &mut x {*v=self.val()?;}
        Ok(Ext::from_basis_coefficients_fn(|i|x[i]))
    }
    fn exts(&mut self,n:usize)->Result<Vec<Ext>> {
        (0..n).map(|_|self.ext()).collect()
    }
    fn roots(&mut self)->Result<Vec<[u8;64]>> {
        (0..8).map(|_|Ok(self.take(64)?.try_into().unwrap())).collect()
    }
}
fn append_ext(out:&mut Vec<u8>,x:Ext) {
    for v in <Ext as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&x){out.extend(v.to_unique_u32().to_le_bytes())}
}
fn checked_inverse(denominator:Ext,witness:Ext)->Result<Ext> {
    require(denominator*witness==Ext::ONE,3)?;Ok(witness)
}
struct Base {evaluations:Vec<Ext>,roots:Vec<[u8;64]>,final_poly:Ext,outputs:[Val;12],inverses:[Ext;3]}
impl Base {
    fn read(data:&[u8])->Result<Self> {
        require(data.len()==BASE_BYTES,4)?;let mut r=Reader{data,at:0};
        let evaluations=r.exts(267)?;let roots=r.roots()?;let final_poly=r.ext()?;
        let mut outputs=[Val::ZERO;12];for v in &mut outputs {*v=r.val()?;}
        let inverses=[r.ext()?,r.ext()?,r.ext()?];
        require(r.at==BASE_BYTES,4)?;Ok(Self{evaluations,roots,final_poly,outputs,inverses})
    }
}
struct Challenger {input:Vec<u8>,output:[u8;64],remaining:usize}
impl Challenger {
    fn new()->Self {Self{input:PARAM_DOMAIN.to_vec(),output:[0;64],remaining:0}}
    fn observe(&mut self,data:&[u8]){self.input.extend(data);self.remaining=0;}
    fn word(&mut self)->u32 {
        let mut v=0;for i in 0..4 {
            if self.remaining==0 {
                self.output=hybrid_slices(&[&self.input]);self.input.clear();
                self.input.extend(self.output);self.remaining=64;
            }
            self.remaining-=1;v|=(self.output[self.remaining] as u32)<<(8*i);
        }v
    }
    fn ext(&mut self)->Ext {
        Ext::from_basis_coefficients_fn(|_|loop{
            let v=self.word()&0x7fffffff;if v<Val::ORDER_U32 {break Val::new(v)}
        })
    }
}
struct Challenges {alpha:Ext,zeta:Ext,pcs_alpha:Ext,betas:Vec<Ext>,indices:Vec<usize>}
fn transcript(b:&Base,request:[u8;32])->Challenges {
    let mut c=Challenger::new();c.observe(&STARK_SEED);c.observe(&b.roots[1]);c.observe(&PREPROCESSED_ROOT);
    let mut public=Vec::with_capacity(112);
    for v in b.outputs {public.extend(v.to_unique_u32().to_le_bytes());}
    for pair in request.chunks_exact(2){public.extend(Val::new(u16::from_le_bytes(pair.try_into().unwrap()) as u32).to_unique_u32().to_le_bytes());}
    c.observe(&public);let alpha=c.ext();c.observe(&b.roots[2]);c.observe(&b.roots[0]);let zeta=c.ext();
    c.observe(&PCS_SEED);let mut evaluations=Vec::with_capacity(8544);
    for &x in &b.evaluations {append_ext(&mut evaluations,x)}c.observe(&evaluations);let pcs_alpha=c.ext();
    c.observe(&FRI_SEED);let betas=b.roots[3..].iter().map(|r|{c.observe(r);c.ext()}).collect();
    let mut final_poly=Vec::with_capacity(32);append_ext(&mut final_poly,b.final_poly);c.observe(&final_poly);
    let indices=(0..64).map(|_|(c.word()&4095) as usize).collect();
    Challenges{alpha,zeta,pcs_alpha,betas,indices}
}
fn generator(log:usize)->Val {Val::new(GENERATORS[log])}

#[inline(never)]
fn check_outer(b:&Base,c:&Challenges,request:[u8;32])->Result<()> {
    let e=&b.evaluations;let z=c.zeta;let zh=z.exp_power_of_2(8)-Ext::ONE;
    let last=generator(8).exp_u64(255);
    let first_selector=zh*checked_inverse(z-Ext::ONE,b.inverses[0])?;
    let last_selector=zh*checked_inverse(z-Ext::from(last),b.inverses[1])?;
    let vanishing_inverse=checked_inverse(zh,b.inverses[2])?;let transition=z-Ext::from(last);
    let state=e[16..40].to_vec();let mut initial=state.clone();
    let mut full:Vec<_>=(0..24).map(|i|(state[i]+e[240+i]).cube()).collect();
    let mut partial=state.clone();partial[0]=full[0];
    <Layers as GenericPoseidon2LinearLayers<24>>::external_linear_layer(initial.as_mut_slice().try_into().unwrap());
    <Layers as GenericPoseidon2LinearLayers<24>>::external_linear_layer(full.as_mut_slice().try_into().unwrap());
    <Layers as GenericPoseidon2LinearLayers<24>>::internal_linear_layer(partial.as_mut_slice().try_into().unwrap());
    let init=e[264];let f=e[265];let p=e[266];let copy=Ext::ONE-init-f-p;
    let mut acc=Ext::ZERO;
    for i in 0..24 {let expected=init*initial[i]+f*full[i]+p*partial[i]+copy*state[i];
        acc=acc*c.alpha+transition*(e[64+i]-expected);}
    for (i,capacity) in initial_capacity().into_iter().enumerate(){acc=acc*c.alpha+first_selector*(state[14+i]-Ext::from(capacity));}
    for i in 0..12 {acc=acc*c.alpha+last_selector*(state[i]-Ext::from(b.outputs[i]));}
    for (i,pair) in request.chunks_exact(2).enumerate(){
        let limb=Val::new(u16::from_le_bytes(pair.try_into().unwrap()) as u32);
        acc=acc*c.alpha+e[40+i]-Ext::from(limb);
    }
    let zs:Vec<_>=(0..8).map(|i|(z*Val::new(QUOTIENT_SHIFTS[i]).inverse()).exp_power_of_2(8)-Ext::ONE).collect();
    let mut quotient=Ext::ZERO;
    for i in 0..8 {
        let mut weight=Ext::ONE;for j in 0..8 {if i!=j {weight*=zs[j];}}
        weight*=Val::new(QUOTIENT_DENOMINATORS[i]);
        let mut chunk=Ext::ZERO;for j in 0..8 {
            let basis=Ext::from_basis_coefficients_fn(|k|if k==j {Val::ONE}else{Val::ZERO});
            chunk+=e[112+16*i+j]*basis;
        }quotient+=weight*chunk;
    }
    require(acc*vanishing_inverse==quotient,5)
}

/// Derived only by prepare. A program-owned account preserves this byte image.
pub struct QueryCache {powers:Vec<Ext>,at_z:Vec<Ext>,zeta:Ext,betas:Vec<Ext>,
    indices:Vec<usize>,roots:Vec<[u8;64]>,final_poly:Ext}
impl QueryCache {
    pub fn encode(&self)->Vec<u8> {
        let mut out=Vec::with_capacity(CACHE_BYTES);
        for &v in self.powers.iter().chain(&self.at_z).chain(core::iter::once(&self.zeta)).chain(&self.betas){append_ext(&mut out,v)}
        for &i in &self.indices {out.extend((i as u16).to_le_bytes());}
        for r in &self.roots {out.extend(r);}append_ext(&mut out,self.final_poly);
        assert_eq!(out.len(),CACHE_BYTES);out
    }
    pub fn read(data:&[u8])->Result<Self> {
        require(data.len()==CACHE_BYTES,6)?;let mut r=Reader{data,at:0};
        let powers=r.exts(267)?;let at_z=r.exts(12)?;let zeta=r.ext()?;let betas=r.exts(5)?;
        let mut indices=Vec::with_capacity(64);for _ in 0..64 {
            let index=u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
            require(index<4096,6)?;indices.push(index);
        }
        let roots=r.roots()?;let final_poly=r.ext()?;require(r.at==CACHE_BYTES,6)?;
        Ok(Self{powers,at_z,zeta,betas,indices,roots,final_poly})
    }
}
pub fn prepare(data:&[u8],request:[u8;32],commitment:[u8;32])->Result<QueryCache> {
    let b=Base::read(data)?;require(authority_commitment(&b.outputs)==commitment,7)?;
    let c=transcript(&b,request);check_outer(&b,&c,request)?;
    let mut powers=Vec::with_capacity(267);powers.push(Ext::ONE);
    for i in 1..267 {powers.push(powers[i-1]*c.pcs_alpha);}
    let offsets=[0,16,64,112,128,144,160,176,192,208,224,240];let mut at_z=Vec::with_capacity(12);
    for (point,&offset) in offsets.iter().enumerate(){
        let width=if point==1||point==2 {48}else if point==11 {27}else{16};
        at_z.push((0..width).map(|i|powers[offset+i]*b.evaluations[offset+i]).sum());
    }
    let mut indices=c.indices;
    // Every sampled index, including its multiplicity, remains in this
    // conjunction. Sorting improves reuse of ordinary authentication paths.
    indices.sort_unstable();
    Ok(QueryCache{powers,at_z,zeta:c.zeta,betas:c.betas,indices,roots:b.roots,final_poly:b.final_poly})
}
fn reverse(index:usize,bits:usize)->u64 {(index as u32).reverse_bits() as u64>>(32-bits)}
fn combination(powers:&[Ext],row:&[u8],at:usize,start:usize,width:usize)->Result<Ext> {
    let mut r=Reader{data:row,at:4*at};let mut out=Ext::ZERO;
    for i in 0..width {out+=powers[start+i]*r.val()?;}Ok(out)
}
fn merkle(leaf:&[u8],path:&[u8],mut index:usize,height:usize,root:&[u8;64])->Result<()> {
    require(path.len()==height*64&&leaf.len()%4==0,8)?;
    let mut fields=Reader{data:leaf,at:0};while fields.at<leaf.len(){let _=fields.val()?;}
    let mut digest=hybrid_slices(&[b"Parano1dX/leaf",leaf]);
    for sibling in path.chunks_exact(64){
        digest=if index&1==0 {hybrid_slices(&[b"Parano1dX/node",&digest,sibling])}
            else {hybrid_slices(&[b"Parano1dX/node",sibling,&digest])};index>>=1;
    }require(&digest==root,9)
}
/// Each index is fixed by the protected transcript cache. Every query checks
/// four input roots, five FRI roots, the complete fold chain and final value.
pub fn check_query(cache:&QueryCache,position:usize,data:&[u8])->Result<()> {
    require(position<64&&data.len()==QUERY_BYTES,10)?;
    let mut r=Reader{data,at:0};let mut leaves=[&[][..];9];let mut paths=[&[][..];9];
    for (leaf,&len) in leaves.iter_mut().zip(&LEAF_BYTES){*leaf=r.take(len)?;}
    for (path,&height) in paths.iter_mut().zip(&HEIGHTS){*path=r.take(height*64)?;}
    let inverse_hint=r.ext()?;let next_inverse_hint=r.ext()?;require(r.at==QUERY_BYTES,10)?;
    let mut index=cache.indices[position];
    for i in 0..4 {let root=if i==3 {&PREPROCESSED_ROOT}else{&cache.roots[i]};
        merkle(leaves[i],paths[i],index,12,root)?;}
    let x=Val::GENERATOR*generator(12).exp_u64(reverse(index,12));
    let inverse=checked_inverse(cache.zeta-Ext::from(x),inverse_hint)?;
    let inverse_next=checked_inverse(cache.zeta*generator(8)-Ext::from(x),next_inverse_hint)?;
    let p=&cache.powers;let z=&cache.at_z;
    let mut reduced=(z[0]-combination(p,leaves[0],0,0,16)?)*inverse;
    reduced+=(z[1]-combination(p,leaves[1],0,16,48)?)*inverse;
    reduced+=(z[2]-combination(p,leaves[1],0,64,48)?)*inverse_next;
    for m in 0..8 {reduced+=(z[3+m]-combination(p,leaves[2],26*m,112+16*m,16)?)*inverse;}
    reduced+=(z[11]-combination(p,leaves[3],0,240,27)?)*inverse;
    let mut log_height=12;
    for round in 0..5 {
        let log_arity=if round==4 {1}else{2};let arity=1<<log_arity;
        let mut row=[Ext::ZERO;4];let mut reader=Reader{data:leaves[4+round],at:0};
        for v in &mut row[..arity] {*v=reader.ext()?;}
        require(row[index&(arity-1)]==reduced,11)?;
        index>>=log_arity;log_height-=log_arity;
        merkle(leaves[4+round],paths[4+round],index,log_height,&cache.roots[3+round])?;
        let inverse_start=generator(log_height+log_arity).exp_u64(
            (1u64<<(log_height+log_arity))-reverse(index,log_height));
        let beta=cache.betas[round]*inverse_start;
        reduced=if arity==2 {(row[0]+row[1]+(row[0]-row[1])*beta)*Val::new((Val::ORDER_U32+1)/2)}
        else {
            let a0=row[0]+row[1];let a1=row[0]-row[1];let a2=row[2]+row[3];
            let a3=(row[2]-row[3])*(-generator(2));
            let c0=a0+a2;let c1=a1+a3;let c2=a0-a2;let c3=a1-a3;
            (c0+beta*(c1+beta*(c2+beta*c3)))*Val::new(4).inverse()
        };
    }require(reduced==cache.final_poly,12)
}

/// Lossless delta transport relative to the previous fully verified query.
/// A twelve-byte bitmap selects literal leaves, path nodes and inverse hints.
/// Every reconstructed query passes the ordinary verifier before retention.
pub fn expand_delta(previous:&[u8],encoded:&[u8])->Result<Vec<u8>> {
    require(previous.len()==QUERY_BYTES&&encoded.len()>=DELTA_HEADER_BYTES
        &&encoded.len()<=QUERY_BYTES+DELTA_HEADER_BYTES,13)?;
    require(encoded[11]&0xfc==0,14)?;
    let mut out=previous.to_vec();let mut at=0;let mut source=DELTA_HEADER_BYTES;
    let mut item=0;
    for len in LEAF_BYTES.into_iter().chain(core::iter::repeat_n(64,79)).chain([32,32]) {
        if encoded[item/8]&(1<<(item%8))!=0 {
            let bytes=encoded.get(source..source+len).ok_or(StreamError(13))?;
            out[at..at+len].copy_from_slice(bytes);source+=len;
        }
        at+=len;item+=1;
    }
    require(item==90&&at==QUERY_BYTES&&source==encoded.len(),15)?;Ok(out)
}

/// Checks the next complete group atomically. The host commits the returned
/// final witness and counter only after every query in the group succeeds.
pub fn check_delta_batch(cache:&QueryCache,position:usize,previous:&[u8],
    encoded:&[u8],batch_size:usize)->Result<(Vec<u8>,usize)> {
    require((1..=6).contains(&batch_size)&&position<64,16)?;
    let count=batch_size.min(64-position);
    require(encoded.first()==Some(&(count as u8)),17)?;
    let mut reader=Reader{data:encoded,at:1};let mut witness=previous.to_vec();
    for i in 0..count {
        let len=u16::from_le_bytes(reader.take(2)?.try_into().unwrap()) as usize;
        let next=expand_delta(&witness,reader.take(len)?)?;
        check_query(cache,position+i,&next)?;witness=next;
    }
    require(reader.at==encoded.len(),18)?;Ok((witness,position+count))
}

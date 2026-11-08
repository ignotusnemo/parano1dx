//! Fixed, aligned proof transport for the pinned backend.
//!
//! Large typed vectors are read from the sealed account through an invocation
//! allocator arena on SBF. Host decoding creates owned vectors. Both paths
//! validate lengths, alignment, field representations and canonical padding.
use alloc::vec::Vec;
use core::{marker::PhantomData,mem::size_of,ops::Deref};
use p3_field::PrimeField32;
use p3_fri::{BatchMultiOpening,CommitPhaseMultiStep,FriProof};
use p3_merkle_tree::PrunedMerklePaths;
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Commitments,OpenedValues,PreprocessedOpenedValues};
use crate::{Proof,Val,Ext,ValMmcs,ExtMmcs,TRACE_LOG,NUM_QUERIES};

type Digest=[u64;8];
type Cap=MerkleCap<Val,Digest>;
type Multi=(Vec<Vec<Vec<Val>>>,PrunedMerklePaths<u64,8>);
const MAGIC:&[u8;8]=b"P1DXF002";
#[derive(Debug,Clone,Copy)]
pub struct WireError(pub u32);

/// The proof cannot outlive or expose mutable access to its input account.
pub struct ProofView<'a> { proof:Proof,hints:Vec<Vec<Vec<Ext>>>,_input:PhantomData<&'a mut [u8]> }
impl Deref for ProofView<'_> {type Target=Proof;fn deref(&self)->&Proof {&self.proof}}
impl ProofView<'_> {pub fn hints(&self)->&[Vec<Vec<Ext>>] {&self.hints}}

/// Record pointer locations in a verifier-created metadata arena. The arena
/// is private program-owned account data, built from a fully validated wire
/// proof by this exact binary. Offsets are relative to the whole account.
#[cfg(target_os="solana")]
pub fn image_relocations(view:&ProofView<'_>,base:usize,account_len:usize,
    image_start:usize,image_end:usize,out:&mut [u32])->Result<usize,WireError> {
    struct Relocations<'a>{base:usize,end:usize,lo:usize,hi:usize,out:&'a mut[u32],n:usize}
    impl Relocations<'_> {
        fn header(&mut self,header:*const u8,bytes:usize,pointer:usize,len:usize)->Result<(),WireError> {
            let h=header as usize;
            if h<self.lo||h.checked_add(bytes).ok_or(WireError(30))?>self.hi {return Err(WireError(31))}
            if len==0 {return Ok(())}
            if pointer<self.base||pointer.checked_add(len).ok_or(WireError(30))?>self.end {return Err(WireError(32))}
            let mut found=None;
            for i in 0..bytes/size_of::<usize>() {
                if unsafe{header.cast::<usize>().add(i).read()}==pointer {
                    if found.is_some() {return Err(WireError(33))} found=Some(h-self.base+i*size_of::<usize>());
                }
            }
            let at=found.ok_or(WireError(34))?;
            *self.out.get_mut(2*self.n).ok_or(WireError(35))?=u32::try_from(at).map_err(|_|WireError(36))?;
            *self.out.get_mut(2*self.n+1).ok_or(WireError(35))?=
                u32::try_from(pointer-self.base).map_err(|_|WireError(36))?;
            self.n+=1;Ok(())
        }
        fn vec<T>(&mut self,v:&Vec<T>)->Result<(),WireError> {
            self.header((v as *const Vec<T>).cast(),size_of::<Vec<T>>(),v.as_ptr() as usize,
                v.capacity().checked_mul(size_of::<T>()).ok_or(WireError(30))?)
        }
        fn v2<T>(&mut self,v:&Vec<Vec<T>>)->Result<(),WireError> {
            self.vec(v)?;for x in v {self.vec(x)?}Ok(())
        }
        fn v3<T>(&mut self,v:&Vec<Vec<Vec<T>>>)->Result<(),WireError> {
            self.vec(v)?;for x in v {self.v2(x)?}Ok(())
        }
        fn v4<T>(&mut self,v:&Vec<Vec<Vec<Vec<T>>>>)->Result<(),WireError> {
            self.vec(v)?;for x in v {self.v3(x)?}Ok(())
        }
        fn cap(&mut self,c:&Cap)->Result<(),WireError> {
            if size_of::<Cap>()!=size_of::<Vec<Digest>>() {return Err(WireError(37))}
            self.header((c as *const Cap).cast(),size_of::<Cap>(),c.roots().as_ptr() as usize,
                core::mem::size_of_val(c.roots()))
        }
        fn multi(&mut self,m:&Multi)->Result<(),WireError> {self.v3(&m.0)?;self.vec(&m.1.sibling_hashes)}
        fn optional<T>(&mut self,v:&Option<Vec<T>>)->Result<(),WireError> {
            if let Some(x)=v {self.vec(x)?}Ok(())
        }
    }
    let mut r=Relocations{base,end:base.checked_add(account_len).ok_or(WireError(30))?,
        lo:image_start,hi:image_end,out,n:0};
    r.v3(&view.hints)?;let p=&view.proof;
    r.cap(&p.commitments.trace)?;r.cap(&p.commitments.quotient_chunks)?;
    if let Some(c)=&p.commitments.random {r.cap(c)?}
    let o=&p.opened_values;r.vec(&o.trace_local)?;r.optional(&o.trace_next)?;
    if let Some(x)=&o.preprocessed {r.vec(&x.local)?;r.optional(&x.next)?}
    r.v2(&o.quotient_chunks)?;r.optional(&o.random)?;r.v4(&p.opening_proof.0)?;
    let f=&p.opening_proof.1;r.vec(&f.commit_phase_commits)?;
    for c in &f.commit_phase_commits {r.cap(c)?}r.vec(&f.commit_pow_witnesses)?;
    r.vec(&f.input_openings)?;
    for x in &f.input_openings {r.v3(&x.opened_values)?;r.multi(&x.opening_proof)?}
    r.vec(&f.commit_phase_openings)?;
    for x in &f.commit_phase_openings {r.v2(&x.sibling_values)?;r.multi(&x.opening_proof)?}
    r.vec(&f.final_poly)?;Ok(r.n)
}

// These three layouts are repr(transparent) over initialized integer arrays.
// No references, pointers or padding occur in any encoded vector element.
unsafe trait Pod:Copy {fn valid(bytes:&[u8])->bool;}
fn valid_fields(bytes:&[u8])->bool {
    bytes.chunks_exact(4).all(|x|u32::from_le_bytes(x.try_into().unwrap())<Val::ORDER_U32)
}
unsafe impl Pod for Val {fn valid(bytes:&[u8])->bool {valid_fields(bytes)}}
unsafe impl Pod for Ext {fn valid(bytes:&[u8])->bool {valid_fields(bytes)}}
unsafe impl Pod for Digest {fn valid(_bytes:&[u8])->bool {true}}

#[cfg(target_os="solana")]
unsafe extern "C" {
    fn parano1dx_register_mapped(start:*mut u8,len:usize)->u64;
    fn parano1dx_arm_mapped(start:*const u8,len:usize,alignment:usize)->u64;
}

struct Writer {out:Vec<u8>}
impl Writer {
    fn pad(&mut self) {while self.out.len()%8!=0 {self.out.push(0)}}
    fn word(&mut self,n:usize) {self.pad();self.out.extend((n as u64).to_le_bytes());}
    fn raw<T:Pod>(&mut self,x:&[T]) {
        self.word(x.len());
        let bytes=unsafe{core::slice::from_raw_parts(x.as_ptr().cast::<u8>(),core::mem::size_of_val(x))};
        self.out.extend(bytes);self.pad();
    }
    fn v2<T:Pod>(&mut self,x:&[Vec<T>]) {self.word(x.len());for a in x {self.raw(a)}}
    fn v3<T:Pod>(&mut self,x:&[Vec<Vec<T>>]) {self.word(x.len());for a in x {self.v2(a)}}
    fn v4<T:Pod>(&mut self,x:&[Vec<Vec<Vec<T>>>]) {self.word(x.len());for a in x {self.v3(a)}}
    fn optional<T:Pod>(&mut self,x:Option<&Vec<T>>) {self.word(usize::from(x.is_some()));if let Some(x)=x {self.raw(x)}}
    fn cap(&mut self,x:&Cap) {self.raw(x.roots())}
    fn multi(&mut self,x:&Multi) {self.v3(&x.0);self.raw(&x.1.sibling_hashes)}
}

pub fn encode_proof(p:&Proof,hints:&[Vec<Vec<Ext>>])->Vec<u8> {
    assert!(cfg!(target_endian="little"));
    assert_eq!(size_of::<Val>(),4);assert_eq!(size_of::<Ext>(),32);
    let mut w=Writer{out:MAGIC.to_vec()};w.v3(hints);w.word(p.degree_bits);w.raw(&[p.ood_pow_witness]);
    w.cap(&p.commitments.trace);w.cap(&p.commitments.quotient_chunks);
    w.word(usize::from(p.commitments.random.is_some()));if let Some(x)=&p.commitments.random {w.cap(x)}
    let o=&p.opened_values;w.raw(&o.trace_local);w.optional(o.trace_next.as_ref());
    w.word(usize::from(o.preprocessed.is_some()));
    if let Some(x)=&o.preprocessed {w.raw(&x.local);w.optional(x.next.as_ref())}
    w.v2(&o.quotient_chunks);w.optional(o.random.as_ref());
    w.v4(&p.opening_proof.0);let f=&p.opening_proof.1;
    w.raw(&[f.batch_pow_witness]);w.word(f.commit_phase_commits.len());
    for c in &f.commit_phase_commits {w.cap(c)}
    w.raw(&f.commit_pow_witnesses);w.word(f.input_openings.len());
    for x in &f.input_openings {w.v3(&x.opened_values);w.multi(&x.opening_proof)}
    w.word(f.commit_phase_openings.len());
    for x in &f.commit_phase_openings {w.v2(&x.sibling_values);w.multi(&x.opening_proof)}
    w.raw(&f.final_poly);w.raw(&[f.query_pow_witness]);w.pad();w.out
}

struct Reader<'a> {bytes:&'a [u8],offset:usize,headers:usize,validate_fields:bool}
impl<'a> Reader<'a> {
    fn pad(&mut self)->Result<(),WireError> {
        let end=(self.offset+7)&!7;
        let pad=self.bytes.get(self.offset..end).ok_or(WireError(1))?;
        if pad.iter().any(|&x|x!=0) {return Err(WireError(2))}
        self.offset=end;Ok(())
    }
    fn word(&mut self,max:usize)->Result<usize,WireError> {
        self.pad()?;let x=self.bytes.get(self.offset..self.offset+8).ok_or(WireError(3))?;
        self.offset+=8;let n=u64::from_le_bytes(x.try_into().unwrap());
        if n>max as u64 {return Err(WireError(4))} Ok(n as usize)
    }
    fn raw<T:Pod>(&mut self,max:usize)->Result<Vec<T>,WireError> {
        self.headers+=1;if self.headers>4096 {return Err(WireError(5))}
        let n=self.word(max)?;let len=n.checked_mul(size_of::<T>()).ok_or(WireError(6))?;
        let end=self.offset.checked_add(len).ok_or(WireError(7))?;
        let bytes=self.bytes.get(self.offset..end).ok_or(WireError(8))?;
        if self.validate_fields&&!T::valid(bytes) {return Err(WireError(9))}
        self.offset=end;self.pad()?;
        if n==0 {return Ok(Vec::new())}
        #[cfg(target_os="solana")]
        {
            if bytes.as_ptr() as usize%core::mem::align_of::<T>()!=0 {return Err(WireError(10))}
            if unsafe{parano1dx_arm_mapped(bytes.as_ptr(),len,core::mem::align_of::<T>())}!=0 {return Err(WireError(11))}
            // The custom allocator allocates this exact, initialized writable
            // account subregion. Dropping it releases the view, preserving data.
            let mut out=Vec::<T>::with_capacity(n);unsafe{out.set_len(n)};Ok(out)
        }
        #[cfg(not(target_os="solana"))]
        {
            let mut out=Vec::with_capacity(n);
            for i in 0..n {out.push(unsafe{bytes.as_ptr().add(i*size_of::<T>()).cast::<T>().read_unaligned()})}
            Ok(out)
        }
    }
    fn v2<T:Pod>(&mut self)->Result<Vec<Vec<T>>,WireError> {
        let n=self.word(1024)?;let mut out=Vec::with_capacity(n);
        for _ in 0..n {out.push(self.raw(4096)?)}Ok(out)
    }
    fn v3<T:Pod>(&mut self)->Result<Vec<Vec<Vec<T>>>,WireError> {
        let n=self.word(NUM_QUERIES+16)?;let mut out=Vec::with_capacity(n);
        for _ in 0..n {out.push(self.v2()?)}Ok(out)
    }
    fn v4<T:Pod>(&mut self)->Result<Vec<Vec<Vec<Vec<T>>>>,WireError> {
        let n=self.word(32)?;let mut out=Vec::with_capacity(n);
        for _ in 0..n {out.push(self.v3()?)}Ok(out)
    }
    fn optional<T:Pod>(&mut self)->Result<Option<Vec<T>>,WireError> {
        if self.word(1)?==0 {Ok(None)} else {Ok(Some(self.raw(4096)?))}
    }
    fn scalar<T:Pod>(&mut self)->Result<T,WireError> {
        let x=self.raw::<T>(1)?;if x.len()!=1 {return Err(WireError(12))}Ok(x[0])
    }
    fn cap(&mut self)->Result<Cap,WireError> {
        let x=self.raw::<Digest>(1)?;if x.len()!=1 {return Err(WireError(13))}Ok(Cap::new(x))
    }
    fn multi(&mut self)->Result<Multi,WireError> {
        Ok((self.v3()?,PrunedMerklePaths{sibling_hashes:self.raw(4096)?}))
    }
}

pub fn decode_proof(bytes:&mut [u8])->Result<ProofView<'_>,WireError> {
    decode_inner(bytes,true)
}
/// The program must previously validate these exact immutable account bytes
/// with decode_proof before setting its protected sealed flag.
pub unsafe fn decode_validated_proof(bytes:&mut [u8])->Result<ProofView<'_>,WireError> {
    decode_inner(bytes,false)
}
fn decode_inner(bytes:&mut [u8],validate_fields:bool)->Result<ProofView<'_>,WireError> {
    if !cfg!(target_endian="little")||bytes.len()>400_000||bytes.get(..8)!=Some(MAGIC) {return Err(WireError(20))}
    #[cfg(target_os="solana")]
    if unsafe{parano1dx_register_mapped(bytes.as_mut_ptr(),bytes.len())}!=0 {return Err(WireError(21))}
    let mut r=Reader{bytes,offset:8,headers:0,validate_fields};
    let hints=r.v3::<Ext>()?;
    let degree_bits=r.word(TRACE_LOG+1)?;if degree_bits!=TRACE_LOG+1 {return Err(WireError(22))}
    let ood_pow_witness=r.scalar::<Val>()?;
    let trace=r.cap()?;let quotient_chunks=r.cap()?;
    let random=if r.word(1)?==0 {None} else {Some(r.cap()?)};
    let commitments=Commitments{trace,quotient_chunks,random};
    let trace_local=r.raw::<Ext>(4096)?;let trace_next=r.optional::<Ext>()?;
    let preprocessed=if r.word(1)?==0 {None} else {Some(PreprocessedOpenedValues{local:r.raw::<Ext>(4096)?,next:r.optional::<Ext>()?})};
    let quotient_chunks=r.v2::<Ext>()?;let random=r.optional::<Ext>()?;
    let opened_values=OpenedValues{trace_local,trace_next,preprocessed,quotient_chunks,random};
    let random_openings=r.v4::<Ext>()?;
    let batch_pow_witness=r.scalar::<Val>()?;
    let n=r.word(16)?;let mut commit_phase_commits=Vec::with_capacity(n);
    for _ in 0..n {commit_phase_commits.push(r.cap()?)}
    let commit_pow_witnesses=r.raw::<Val>(16)?;
    let n=r.word(16)?;let mut input_openings=Vec::with_capacity(n);
    for _ in 0..n {input_openings.push(BatchMultiOpening::<Val,ValMmcs>{opened_values:r.v3()?,opening_proof:r.multi()?})}
    let n=r.word(16)?;let mut commit_phase_openings=Vec::with_capacity(n);
    for _ in 0..n {commit_phase_openings.push(CommitPhaseMultiStep::<Ext,ExtMmcs>{sibling_values:r.v2()?,opening_proof:r.multi()?})}
    let final_poly=r.raw::<Ext>(4096)?;let query_pow_witness=r.scalar::<Val>()?;
    r.pad()?;if r.offset!=bytes.len() {return Err(WireError(23))}
    let fri=FriProof {batch_pow_witness,commit_phase_commits,commit_pow_witnesses,input_openings,
        commit_phase_openings,final_poly,query_pow_witness};
    Ok(ProofView{proof:Proof {commitments,opened_values,opening_proof:(random_openings,fri),degree_bits,ood_pow_witness},hints,_input:PhantomData})
}

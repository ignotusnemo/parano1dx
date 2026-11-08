use parano1dx_vault_auth::{parameter_id,withdrawal_id,sha256,stream};
use solana_program::{
    account_info::{AccountInfo,next_account_info},entrypoint,entrypoint::ProgramResult,
    program::{invoke,invoke_signed},program_error::ProgramError,pubkey::Pubkey,
    rent::Rent,sysvar::Sysvar,clock::Clock,system_instruction,system_program,
};
#[cfg(target_os="solana")]
mod allocator {
    use core::{alloc::{GlobalAlloc,Layout},ptr::NonNull};
    use talc::{Talc,ErrOnOom,Span};
    pub struct Allocator;
    unsafe fn heap()->&'static mut Talc<ErrOnOom> {
        let marker=0x300000000 as *mut u64;let pointer=0x300000200 as *mut Talc<ErrOnOom>;
        unsafe {
            if marker.read()==0 {
                assert!(core::mem::size_of::<Talc<ErrOnOom>>()<=3584);
                pointer.write(Talc::new(ErrOnOom));
                (*pointer).claim(Span::from_base_size(0x300001000 as *mut u8,258_048)).unwrap();marker.write(1);
            }&mut *pointer
        }
    }
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self,l:Layout)->*mut u8 {unsafe{heap().malloc(l)}.map_or(core::ptr::null_mut(),|x|x.as_ptr())}
        unsafe fn dealloc(&self,p:*mut u8,l:Layout) {if let Some(p)=NonNull::new(p){unsafe{heap().free(p,l)}}}
    }
    #[global_allocator]
    static HEAP:Allocator=Allocator;
}
entrypoint!(process_instruction);
const CAP:&[u8]=include_bytes!("../../results/preprocessed-cap.bin");
const VAULT_LEN:usize=80;
const HEADER:usize=256;
const PREVIOUS:usize=HEADER+stream::CACHE_BYTES;
const WINDOW:usize=PREVIOUS+stream::QUERY_BYTES;
const MAX_BATCH:usize=5;
const MAX_WINDOW:usize=1+MAX_BATCH*(2+stream::QUERY_BYTES+stream::DELTA_HEADER_BYTES);
const BASE_FRAME:u16=u16::MAX;
#[cfg(not(feature="wide-transport"))]
const CHUNK_BYTES:usize=960;
#[cfg(feature="wide-transport")]
const CHUNK_BYTES:usize=3584;
const VAULT_SEED:&[u8]=b"Parano1dX-vault";
const VAULT_MAGIC:&[u8;8]=b"BANKv001";
#[cfg(not(feature="wide-transport"))]
const JOB_MAGIC:&[u8;8]=b"FLOWv002";
#[cfg(feature="wide-transport")]
const JOB_MAGIC:&[u8;8]=b"FLOWv003";
fn error(code:u32)->ProgramError {ProgramError::Custom(code)}
fn require(ok:bool,code:u32)->ProgramResult {if ok {Ok(())}else{Err(error(code))}}
fn u64_at(d:&[u8],i:usize)->Result<u64,ProgramError>{Ok(u64::from_le_bytes(d.get(i..i+8).ok_or(error(100))?.try_into().unwrap()))}
fn u32_at(d:&[u8],i:usize)->Result<usize,ProgramError>{Ok(u32::from_le_bytes(d.get(i..i+4).ok_or(error(100))?.try_into().unwrap()) as usize)}
fn frame_at(d:&[u8],i:usize)->Result<u16,ProgramError>{Ok(u16::from_le_bytes(d.get(i..i+2).ok_or(error(100))?.try_into().unwrap()))}
fn frame(d:&[u8])->Result<(u16,usize),ProgramError>{
    require(d.len()>=WINDOW+stream::BASE_BYTES&&d.len()<=WINDOW+MAX_WINDOW&&&d[..8]==JOB_MAGIC,180)?;
    match d[8] {
        0=>Ok((BASE_FRAME,stream::BASE_BYTES)),
        1=>{let index=u64_at(d,113)?;require(index<64&&(1..=MAX_BATCH).contains(&(d[133] as usize)),181)?;
            Ok((index as u16,d.len()-WINDOW))},
        _=>Err(error(181)),
    }
}
pub fn process_instruction(pid:&Pubkey,accounts:&[AccountInfo],data:&[u8])->ProgramResult {
    let (&op,args)=data.split_first().ok_or(error(100))?;
    match op {
        0=>initialize_vault(pid,accounts,args),1=>initialize_job(pid,accounts,args),
        2=>upload_window(pid,accounts,args),3=>reset_window(pid,accounts,args),
        4=>verify_step(pid,accounts,args,false),5=>close_job(pid,accounts,args),
        6=>verify_step(pid,accounts,args,true),_=>Err(error(101)),
    }
}
fn initialize_vault(pid:&Pubkey,accounts:&[AccountInfo],args:&[u8])->ProgramResult {
    require(args.len()==32,110)?;let mut iter=accounts.iter();
    let payer=next_account_info(&mut iter)?;let vault=next_account_info(&mut iter)?;let system=next_account_info(&mut iter)?;
    require(payer.is_signer&&payer.is_writable&&vault.is_writable,111)?;require(system.key==&system_program::id(),112)?;
    let c:[u8;32]=args.try_into().unwrap();let (expected,bump)=Pubkey::find_program_address(&[VAULT_SEED,&c],pid);
    require(vault.key==&expected&&vault.owner==&system_program::id()&&vault.data_is_empty(),113)?;
    let rent=Rent::get()?.minimum_balance(VAULT_LEN);
    if vault.lamports()<rent {invoke(&system_instruction::transfer(payer.key,vault.key,rent-vault.lamports()),&[payer.clone(),vault.clone(),system.clone()])?;}
    let bump=[bump];let seeds:&[&[u8]]=&[VAULT_SEED,&c,&bump];
    invoke_signed(&system_instruction::allocate(vault.key,VAULT_LEN as u64),&[vault.clone(),system.clone()],&[seeds])?;
    invoke_signed(&system_instruction::assign(vault.key,pid),&[vault.clone(),system.clone()],&[seeds])?;
    let mut d=vault.try_borrow_mut_data()?;d[..8].copy_from_slice(VAULT_MAGIC);d[8..40].copy_from_slice(&c);
    d[40..48].copy_from_slice(&0u64.to_le_bytes());d[48..80].copy_from_slice(&parameter_id(CAP));Ok(())
}
fn initialize_job(pid:&Pubkey,accounts:&[AccountInfo],args:&[u8])->ProgramResult {
    require(args.len()==65&&(1..=MAX_BATCH).contains(&(args[64] as usize)),120)?;let mut iter=accounts.iter();let job=next_account_info(&mut iter)?;let uploader=next_account_info(&mut iter)?;
    require(job.owner==pid&&job.is_writable&&job.is_signer&&uploader.is_signer,121)?;let mut d=job.try_borrow_mut_data()?;
    require(d.len()>=WINDOW+stream::BASE_BYTES&&d.len()<=WINDOW+MAX_WINDOW&&d[..HEADER].iter().all(|&x|x==0),123)?;
    d[..8].copy_from_slice(JOB_MAGIC);d[8]=0;d[17..49].copy_from_slice(&args[..32]);
    d[49..81].copy_from_slice(uploader.key.as_ref());d[81..113].copy_from_slice(&args[32..64]);d[133]=args[64];Ok(())
}
fn upload_window(pid:&Pubkey,accounts:&[AccountInfo],args:&[u8])->ProgramResult {
    require(args.len()>12,130)?;let mut iter=accounts.iter();let job=next_account_info(&mut iter)?;let uploader=next_account_info(&mut iter)?;
    require(job.owner==pid&&job.is_writable&&uploader.is_signer,131)?;
    let mut d=job.try_borrow_mut_data()?;let (expected,maximum)=frame(&d)?;
    require(d[49..81]==uploader.key.to_bytes()&&frame_at(args,0)?==expected,133)?;
    require(u32_at(args,4)?==u32_at(&d,129)?,135)?;
    let len=frame_at(args,2)? as usize;let offset=u32_at(args,8)?;
    require(len>0&&len<=maximum&&(expected!=BASE_FRAME||len==stream::BASE_BYTES),134)?;
    let mask=u64_at(&d,121)?;
    if mask==0 {d[13..17].copy_from_slice(&(len as u32).to_le_bytes());}
    else {require(u32_at(&d,13)?==len,134)?;}
    require(offset<len&&offset%CHUNK_BYTES==0&&offset/CHUNK_BYTES<64,134)?;
    let end=(offset+CHUNK_BYTES).min(len);
    require(args.len()-12==end-offset,134)?;
    let bit=1u64<<(offset/CHUNK_BYTES);
    if mask&bit!=0 {return require(d[WINDOW+offset..WINDOW+end]==args[12..],136);}
    let received=u32_at(&d,9)?.checked_add(end-offset).ok_or(error(134))?;
    require(received<=len,134)?;
    d[WINDOW+offset..WINDOW+end].copy_from_slice(&args[12..]);
    d[9..13].copy_from_slice(&(received as u32).to_le_bytes());
    d[121..129].copy_from_slice(&(mask|bit).to_le_bytes());Ok(())
}
fn reset_window(pid:&Pubkey,accounts:&[AccountInfo],args:&[u8])->ProgramResult {
    require(args.len()==6,140)?;let mut iter=accounts.iter();let job=next_account_info(&mut iter)?;let uploader=next_account_info(&mut iter)?;
    require(job.owner==pid&&job.is_writable&&uploader.is_signer,141)?;
    let mut d=job.try_borrow_mut_data()?;let (expected,_)=frame(&d)?;
    require(d[49..81]==uploader.key.to_bytes()&&frame_at(args,0)?==expected&&u32_at(args,2)?==u32_at(&d,129)?,142)?;
    let epoch=(u32_at(&d,129)? as u32).checked_add(1).ok_or(error(143))?;
    // Retries preserve the accepted cache and contiguous query counter.
    d[9..17].fill(0);d[121..129].fill(0);d[129..133].copy_from_slice(&epoch.to_le_bytes());Ok(())
}
fn verify_step(pid:&Pubkey,accounts:&[AccountInfo],args:&[u8],allow_incomplete:bool)->ProgramResult {
    require(args.len()==30,150)?;let mut iter=accounts.iter();
    let vault=next_account_info(&mut iter)?;let recipient=next_account_info(&mut iter)?;let job=next_account_info(&mut iter)?;
    require(vault.is_writable&&recipient.is_writable&&job.is_writable&&vault.owner==pid&&job.owner==pid,151)?;
    require(vault.key!=recipient.key&&vault.key!=job.key&&recipient.key!=job.key,152)?;
    let nonce=u64_at(args,0)?;let amount=u64_at(args,8)?;let expires=u64_at(args,16)?;
    let vd=vault.try_borrow_data()?;require(vd.len()==VAULT_LEN&&&vd[..8]==VAULT_MAGIC,153)?;
    let c:[u8;32]=vd[8..40].try_into().unwrap();require(u64_at(&vd,40)?==nonce,154)?;require(vd[48..80]==parameter_id(CAP),155)?;
    let (expected,_)=Pubkey::find_program_address(&[VAULT_SEED,&c],pid);require(vault.key==&expected,156)?;drop(vd);
    require(Clock::get()?.slot<=expires&&amount>0,157)?;
    let remaining=vault.lamports().checked_sub(amount).ok_or(error(158))?;require(remaining>=Rent::get()?.minimum_balance(VAULT_LEN),158)?;
    let recipient_balance=recipient.lamports().checked_add(amount).ok_or(error(159))?;let next_nonce=nonce.checked_add(1).ok_or(error(160))?;
    let request=withdrawal_id(pid.to_bytes(),vault.key.to_bytes(),recipient.key.to_bytes(),nonce,amount,expires,parameter_id(CAP));
    let mut d=job.try_borrow_mut_data()?;let (expected,maximum)=frame(&d)?;let len=u32_at(&d,13)?;
    require(d[81..113]==request&&frame_at(args,24)?==expected&&u32_at(args,26)?==u32_at(&d,129)?,163)?;
    require(len>0&&len<=maximum,164)?;
    let chunks=len.div_ceil(CHUNK_BYTES);require(chunks<64,164)?;
    let complete=u32_at(&d,9)?==len&&u64_at(&d,121)?==(1u64<<chunks)-1;
    if allow_incomplete&&!complete {return Ok(());}
    require(complete,164)?;
    if expected==BASE_FRAME {
        require(sha256(&d[WINDOW..WINDOW+len])==d[17..49],165)?;
        let cache=stream::prepare(&d[WINDOW..WINDOW+len],request,c).map_err(|e|error(400+e.0))?.encode();
        d[HEADER..PREVIOUS].copy_from_slice(&cache);d[8]=1;d[9..17].fill(0);d[121..129].fill(0);return Ok(());
    }
    let cache=stream::QueryCache::read(&d[HEADER..PREVIOUS]).map_err(|e|error(400+e.0))?;
    let (query,next)=stream::check_delta_batch(&cache,expected as usize,&d[PREVIOUS..WINDOW],
        &d[WINDOW..WINDOW+len],d[133] as usize).map_err(|e|error(400+e.0))?;
    d[PREVIOUS..WINDOW].copy_from_slice(&query);
    d[113..121].copy_from_slice(&(next as u64).to_le_bytes());d[9..17].fill(0);d[121..129].fill(0);
    if next<64 {return Ok(());}
    d[8]=2;drop(d);vault.try_borrow_mut_data()?[40..48].copy_from_slice(&next_nonce.to_le_bytes());
    **vault.try_borrow_mut_lamports()?=remaining;**recipient.try_borrow_mut_lamports()?=recipient_balance;Ok(())
}
fn close_job(pid:&Pubkey,accounts:&[AccountInfo],args:&[u8])->ProgramResult {
    require(args.is_empty(),170)?;let mut iter=accounts.iter();let job=next_account_info(&mut iter)?;let uploader=next_account_info(&mut iter)?;
    require(job.owner==pid&&job.is_writable&&uploader.is_signer&&uploader.is_writable&&job.key!=uploader.key,171)?;
    let d=job.try_borrow_data()?;require(d.len()>=WINDOW+stream::BASE_BYTES&&d.len()<=WINDOW+MAX_WINDOW&&&d[..8]==JOB_MAGIC&&d[49..81]==uploader.key.to_bytes(),172)?;drop(d);
    let balance=uploader.lamports().checked_add(job.lamports()).ok_or(error(173))?;
    **uploader.try_borrow_mut_lamports()?=balance;**job.try_borrow_mut_lamports()?=0;
    job.resize(0)?;job.assign(&system_program::id());Ok(())
}

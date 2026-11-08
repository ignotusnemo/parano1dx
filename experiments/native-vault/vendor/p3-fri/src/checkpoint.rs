//! Experimental decomposition of the strict verifier into checked phases.
//! Default mode is strict. A checkpoint result covers one phase. Spending
//! requires the complete ordered conjunction in a verifier-owned immutable job.
use alloc::vec::Vec;
use core::mem::size_of;
pub fn mark(stage:u64) {
    #[cfg(target_os="solana")]
    unsafe {
        unsafe extern "C" {fn sol_log_64_(a:u64,b:u64,c:u64,d:u64,e:u64);fn sol_log_compute_units_();}
        sol_log_64_(stage,0,0,0,0);sol_log_compute_units_();
    }
    #[cfg(not(target_os="solana"))]
    let _=stage;
}
#[cfg(not(target_os="solana"))]
extern crate std;

#[cfg(not(target_os="solana"))]
std::thread_local! {
    static STATE:std::cell::RefCell<NativeState>=std::cell::RefCell::new(NativeState::default());
}
#[cfg(not(target_os="solana"))]
#[derive(Default)]
struct NativeState {mode:u64,capture:bool,rows:Vec<Vec<Vec<u8>>>}

#[cfg(target_os="solana")]
unsafe extern "C" {
    fn parano1dx_checkpoint_mode()->u64;
    fn parano1dx_checkpoint_row(round:usize,query:usize,out:*mut u8,len:usize)->u64;
}
pub fn mode()->u64 {
    #[cfg(target_os="solana")]
    {unsafe{parano1dx_checkpoint_mode()}}
    #[cfg(not(target_os="solana"))]
    {STATE.with(|s|s.borrow().mode)}
}
pub fn input_root(batch:usize)->bool {let m=mode();m==0||m==((1u64<<56)|batch as u64)}
pub fn commit_root(round:usize)->bool {let m=mode();m==0||m==((2u64<<56)|round as u64)}
pub fn query(q:usize)->bool {let m=mode();m==0||m==((3u64<<56)|q as u64)}
pub fn has_queries()->bool {let m=mode();m==0||m>>56==3}

#[cfg(not(target_os="solana"))]
pub fn start_recording() {STATE.with(|s|{let mut s=s.borrow_mut();s.mode=0;s.capture=true;s.rows.clear();})}
#[cfg(not(target_os="solana"))]
pub fn take_recorded()->Vec<Vec<Vec<u8>>> {STATE.with(|s|{let mut s=s.borrow_mut();s.capture=false;core::mem::take(&mut s.rows)})}
#[cfg(not(target_os="solana"))]
pub fn set_native_stage(mode:u64,rows:Vec<Vec<Vec<u8>>>) {STATE.with(|s|{let mut s=s.borrow_mut();s.mode=mode;s.capture=false;s.rows=rows;})}

pub fn record<T:Copy>(rows:&[Vec<Vec<Vec<T>>>]) {
    #[cfg(not(target_os="solana"))]
    STATE.with(|s|{let mut s=s.borrow_mut();if s.capture {
        s.rows=rows.iter().map(|round|round.iter().map(|query|{
            assert_eq!(query.len(),1);let row=&query[0];
            unsafe{core::slice::from_raw_parts(row.as_ptr().cast::<u8>(),core::mem::size_of_val(row.as_slice()))}.to_vec()
        }).collect()).collect();
    }});
    #[cfg(target_os="solana")]
    let _=rows;
}

pub fn row<T:Copy>(round:usize,query:usize,len:usize)->Option<Vec<T>> {
    let byte_len=len.checked_mul(size_of::<T>())?;
    let mut out=Vec::<T>::with_capacity(len);
    #[cfg(target_os="solana")]
    if unsafe{parano1dx_checkpoint_row(round,query,out.as_mut_ptr().cast::<u8>(),byte_len)}!=0 {return None}
    #[cfg(not(target_os="solana"))]
    {
        let ok=STATE.with(|s|{let s=s.borrow();let Some(bytes)=s.rows.get(round).and_then(|r|r.get(query)) else {return false};
            if bytes.len()!=byte_len {return false}
            unsafe{core::ptr::copy_nonoverlapping(bytes.as_ptr(),out.as_mut_ptr().cast::<u8>(),byte_len)};true
        });if !ok {return None}
    }
    unsafe{out.set_len(len)};Some(out)
}

pub fn matches<T:Copy+PartialEq>(round:usize,query:usize,actual:&[T])->bool {
    mode()==0||row::<T>(round,query,actual.len()).is_some_and(|x|x==actual)
}

use std::{env,fs,path::PathBuf};
fn main(){
    println!("cargo:rerun-if-env-changed=PARANO1DX_SOLANA_NETWORK_HEX");
    println!("cargo:rerun-if-changed=build.rs");
    let network=match env::var("PARANO1DX_SOLANA_NETWORK_HEX"){
        Ok(hex)=>{assert_eq!(hex.len(),64,"network domain must contain 32 bytes");
            core::array::from_fn(|i|u8::from_str_radix(&hex[2*i..2*i+2],16).expect("network hex"))},
        Err(_)=>*b"Parano1dX local Solana research1",
    };
    fs::write(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("network-domain.bin"),network).unwrap();
}

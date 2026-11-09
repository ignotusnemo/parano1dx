use parano1dx_vault_auth::{sha256,sampler::{positions,Wide},Val};
use p3_field::PrimeField32;
fn main(){let rows:Vec<_>=(0..128u32).map(|i|{let mut b=[0;64];b[..32].copy_from_slice(&sha256(&i.to_le_bytes()));b[32..].copy_from_slice(&sha256(&(i+128).to_le_bytes()));let mut n=Wide::from_bytes(b);let digits:Vec<_>=(0..8).map(|_|n.divide(Val::ORDER_U32)).collect();serde_json::json!({"bytes":b.to_vec(),"positions":positions(b,12).to_vec(),"field_digits":digits})}).collect();println!("{}",serde_json::to_string(&rows).unwrap());}

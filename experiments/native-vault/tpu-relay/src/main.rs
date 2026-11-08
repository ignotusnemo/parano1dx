use std::{collections::{HashMap, HashSet},io::{self,BufRead,Write},net::SocketAddr,time::{Duration,Instant}};
use base64::{Engine,engine::general_purpose::STANDARD};
use solana_client::{rpc_client::RpcClient,connection_cache::ConnectionCache};
use solana_commitment_config::CommitmentConfig;
use solana_connection_cache::client_connection::ClientConnection;
use serde_json::{json,Value};

fn main(){
    let profile=std::env::args().nth(1).expect("private RPC profile path");
    let config:Value=serde_json::from_slice(&std::fs::read(profile).expect("RPC profile")).expect("RPC profile JSON");
    let http=config["http_url"].as_str().unwrap().to_owned();
    let mut secrets=vec![http.clone()];
    if let Ok(url)=url::Url::parse(&http){for(_,value)in url.query_pairs(){secrets.push(value.into_owned());}}
    let clean=|error:String|{let mut s=error;for value in &secrets {s=s.replace(value,"[private RPC]")}s};
    let rpc=RpcClient::new_with_commitment(http,CommitmentConfig::confirmed());
    match rpc.get_genesis_hash(){
        Ok(hash) if hash.to_string()=="EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"=>{},
        Ok(_)=>{println!("{}",json!({"error":"Devnet genesis required"}));return},
        Err(error)=>{println!("{}",json!({"error":clean(error.to_string())}));return},
    }
    let contacts=match rpc.get_cluster_nodes(){
        Ok(nodes)=>nodes.into_iter().filter_map(|n|n.tpu_quic.map(|a|(n.pubkey,a))).collect::<HashMap<_,_>>(),
        Err(error)=>{println!("{}",json!({"error":clean(error.to_string())}));return},
    };
    let cache=ConnectionCache::new("parano1dx_direct_tpu");
    let mut addresses:Vec<SocketAddr>=Vec::new();
    let mut leader_slot=0u64;
    let mut refreshed=Instant::now()-Duration::from_secs(10);
    println!("{}",json!({"ready":true,"transport":"Agave QUIC with explicit leader refresh","fanout_slots":16}));
    io::stdout().flush().unwrap();
    for line in io::stdin().lock().lines(){
        let Ok(line)=line else{break};
        let input:Value=match serde_json::from_str(&line){Ok(v)=>v,Err(_)=>continue};
        if input["op"]=="close"{break}
        let id=input["id"].clone();let started=Instant::now();
        let mut transactions=Vec::new();let mut valid=true;
        if let Some(values)=input["transactions"].as_array(){
            for value in values{
                match value.as_str().and_then(|x|STANDARD.decode(x).ok()){
                    Some(wire) if !wire.is_empty()&&(wire.len()<=1232||wire[0]==0x81&&wire.len()<=4096)=>transactions.push(wire),
                    _=>{valid=false;break},
                }
            }
        }else{valid=false;}
        if !valid||transactions.is_empty()||transactions.len()>64{
            println!("{}",json!({"id":id,"error":"one to 64 serialized transactions required"}));
            io::stdout().flush().unwrap();continue;
        }
        if refreshed.elapsed()>Duration::from_secs(1){
            let refresh=(||{
                let slot=rpc.get_slot_with_commitment(CommitmentConfig::processed())?;
                let leaders=rpc.get_slot_leaders(slot,16)?;
                let mut unique=HashSet::new();
                let next:Vec<_>=leaders.iter().filter_map(|p|contacts.get(&p.to_string()).copied()).filter(|a|unique.insert(*a)).collect();
                Ok::<_,solana_client::client_error::ClientError>((slot,next))
            })();
            match refresh {
                Ok((slot,next)) if !next.is_empty()=>{leader_slot=slot;addresses=next;refreshed=Instant::now();},
                Ok(_)=>{println!("{}",json!({"id":id,"error":"No current leader QUIC addresses"}));io::stdout().flush().unwrap();continue;},
                Err(error)=>{println!("{}",json!({"id":id,"error":clean(error.to_string())}));io::stdout().flush().unwrap();continue;},
            }
        }
        let outcomes=std::thread::scope(|scope|{
            let handles:Vec<_>=addresses.iter().map(|address|{
                let connection=cache.get_connection(address);let wire=&transactions;
                scope.spawn(move||connection.send_data_batch(wire))
            }).collect();
            handles.into_iter().map(|h|h.join().expect("QUIC worker")).collect::<Vec<_>>()
        });
        let delivered=outcomes.iter().filter(|x|x.is_ok()).count();
        let error=if delivered==0 {outcomes.into_iter().find_map(|x|x.err()).map(|e|clean(e.to_string()))} else {None};
        println!("{}",json!({"id":id,"submitted":if delivered>0 {transactions.len()} else {0},"error":error,
            "leader_slot":leader_slot,"leader_addresses":addresses.len(),"successful_leader_connections":delivered,
            "transport_elapsed_ms":started.elapsed().as_secs_f64()*1000.}));
        io::stdout().flush().unwrap();
    }
}

use serde_json;

#[allow(dead_code)]
pub fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    match encoded_value.chars().next() {
        Some('0'..='9') => {
            // Example: "5:hello" -> "hello"
            if let Some((length, rest)) = encoded_value.split_once(':') {
                if let Ok(length) = length.parse::<usize>() {
                    return (rest[..length].to_string().into(), &rest[length..]);
                }
                return (serde_json::Value::Null, "");
            }
        }
        Some('i') => {
            // Example: "i52e" -> "52"
            if let Some((n, rest)) =
                encoded_value
                    .split_at(1)
                    .1
                    .split_once('e')
                    .and_then(|(digit, rest)| {
                        let n = digit.parse::<i64>().ok();
                        Some((n, rest))
                    })
            {
                return (n.into(), rest);
            }
            return (serde_json::Value::Null, "");
        }
        Some('l') => {
            //Example: "l5:helloi52ee" -> [“hello”,52]
            let mut values = Vec::new();
            let mut rest = encoded_value.split_at(1).1;
            while !rest.is_empty() && !rest.starts_with('e') {
                let (v, remainder)= decode_bencoded_value(rest);
                values.push(v);
                rest = remainder;
            }
            return (values.into(), &rest[1..]);
        }
        Some('d') => {
            //Example: "d3:foo3:bar5:helloi52ee" -> {"foo":"bar","hello":52}
            let mut dict = serde_json::Map::new();
            let mut rest = encoded_value.split_at(1).1;
            while !rest.is_empty() && !rest.starts_with('e') {
                let (k, remainder) = decode_bencoded_value(rest);
                let k = match k {
                    serde_json::Value::String(k) => k,
                    k => {
                        panic!("dict keys must be strings, not {k:?}");
                    }
                };
                let (v, remainder) = decode_bencoded_value(remainder);
                dict.insert(k, v);
                rest = remainder;
            }
            return (dict.into(), &rest[1..]);
        }
        _ => {}
    }
    panic!("Unhandled encoded value: {}", encoded_value)
}


// Get Tracker 
use crate::models::Torrent;

use reqwest::Client;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use anyhow::Context;

#[derive(Debug, Clone, Deserialize)]
struct TrackerResponse {
    //interval: u32,
    #[serde(with = "serde_bytes")]
    peers: Vec<u8>,
}


#[derive(Debug, Clone, Serialize)]
struct TrackerRequest {
    //#[serde(serialize_with="hash_encode")]
    //info_hash: [u8; 20],
    peer_id: String,
    port: u16,
    uploaded: usize,
    downloaded: usize,
    left: usize,
    compact: u8,
}

fn hash_encode(t: &[u8; 20]) -> String {
    let encoded: String = t.iter().map(|b| format!("%{:02x}", b)).collect();
    //eprintln!("{encoded}");
    encoded
}

pub async fn get_tracker(t: &Torrent) -> anyhow::Result<Vec<SocketAddrV4>> {
    let info = serde_bencode::to_bytes(&t.info)?;
    let mut hasher = Sha1::new();
    hasher.update(&info);
    let hashed_info = hasher.finalize();
    let tracker_url = reqwest::Url::parse(&format!(
        "{}?info_hash={}",
        t.announce,
        hash_encode(hashed_info[..].try_into()?)
    ))?;
    let client = Client::new().get(tracker_url).query(&TrackerRequest {
        //info_hash: hashed_info[..].try_into()?,
        peer_id: "00112233445566778899".to_string(),
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: t.info.plength,
        compact: 1,
    });
    //eprintln!("{:?}", client);
    let response = client.send().await.context("Tracker request builder")?;
    //eprintln!("{}", response.status());
    //println!("{}", response.text().await?);
    let response = serde_bencode::from_bytes::<TrackerResponse>(&response.bytes().await?)
        .context("Decoding response")?;
    //eprintln!("{response:?}");
    let peers: Vec<_> = response
        .peers
        .chunks_exact(6)
        .map(|c| {
            SocketAddrV4::new(
                Ipv4Addr::new(c[0], c[1], c[2], c[3]),
                u16::from_be_bytes([c[4], c[5]]),
            )
        })
        .collect();
     Ok(peers)
}

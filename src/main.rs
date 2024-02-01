use anyhow::{anyhow, Context, Ok};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
pub mod utils;
pub mod peers;

// Torrent
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
pub mod hashes;
//

// Peers
use reqwest::Client;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
//

// Handshake
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
//

#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Decode { value: String },
    Info { torrent: PathBuf },
    Peers { path: PathBuf },
    Handshake { path: PathBuf, peer: SocketAddr },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Decode { value } => {
            let v = utils::decode_bencoded_value(&value).0;
            println!("{v}");
        }
        Command::Info { torrent } => {
            let dot_torrent = std::fs::read(torrent).context("open torrent file")?;
            let t: Torrent = serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;
            println!("Tracker URL: {}", t.announce);
            if let Keys::SingleFile { length } = t.info.keys {
                println!("Length: {length}");
            } else {
                todo!();
            }
            let info_encoded = serde_bencode::to_bytes(&t.info).context("re-encode info section")?;
            let mut hasher = Sha1::new();
            hasher.update(&info_encoded);
            let info_hash = hasher.finalize();
            println!("Info Hash: {}", hex::encode(info_hash));
            println!("Piece Length: {}", t.info.plength);
            println!("Pieces Hashes:");
            for hash in t.info.pieces.0 {
                println!("{}", hex::encode(hash))
            }
        }
        Command::Peers { path } => {
            let dot_torrent = std::fs::read(path).context("open torrent file")?;
            let t: Torrent = serde_bencode::from_bytes(&dot_torrent).context("parse torrent file")?;
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
            peers.iter().for_each(|p| println!("{p:?}"));
        },
        Command::Handshake { path, peer } => {
            eprintln!("{path:?} {peer:?}");
            let content = std::fs::read(path).context("Reading torrent file")?;
            let t: Torrent = serde_bencode::from_bytes(&content).context("parse torrent file")?;
            let mut tcp_peer = TcpStream::connect(peer)
                .await
                .context("Connecting to peer")?;
            let hs = peers::Handshake::new(t.info.hash()?, b"00112233445566778899".to_owned());
            tcp_peer.write_all(&hs.to_bytes()).await?;
            let mut buf = [0; peers::HANDSHAKE_LEN];
            tcp_peer.read_exact(&mut buf).await?;
            //eprintln!("{buf:?}");
            let hs_resp = peers::Handshake::from_bytes(&buf)?;
            println!("Peer ID: {}", hex::encode(hs_resp.peer_id));
        },
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Torrent {
    announce: String,
    info: Info,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
struct Info {
    name: String,
    #[serde(rename = "piece length")]
    plength: usize,
    pieces: hashes::Hashes,
    #[serde(flatten)]
    keys: Keys,
}

impl Info {
    fn hash(&self) -> anyhow::Result<[u8; 20]> {
        let info = serde_bencode::to_bytes(&self)?;
        let mut hasher = Sha1::new();
        hasher.update(&info);
        let hashed_info = hasher.finalize();
        hashed_info[..].try_into().map_err(|e| anyhow!("{}", e))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum Keys {
    SingleFile { length: usize },
    MultiFile { files: File },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
struct File {
    length: usize,
    path: Vec<String>,
}

// Peers
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

#[derive(Debug, Clone, Deserialize)]
struct TrackerResponse {
    //interval: u32,
    #[serde(with = "serde_bytes")]
    peers: Vec<u8>,
}
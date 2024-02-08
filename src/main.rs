use anyhow::{Context, Ok};
use clap::{Parser, Subcommand};
use core::panic;
use std::path::PathBuf;

pub mod utils;

#[path = "./models/models.rs"]
pub mod models;
use models::Torrent;
use models::Keys;


mod peers;
use peers::Handshake;
use peers::HANDSHAKE_LEN;


// Torrent
use sha1::{Digest, Sha1};
//

// Peers
use std::net::SocketAddrV4;
//

// Handshake
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
//

// Download
use std::sync::Arc;
//

pub mod download_piece;
use download_piece::download_piece;
use download_piece::download_pieces;

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
    #[clap(name = "download_piece")]
    DownloadPiece { 
        #[clap(short, long)]
        output: PathBuf, // Nueva opción -o para el comando DownloadPiece
        path: PathBuf, 
        piece_index: u32 
    },
    Download {
        #[clap(short, long)]
        output: PathBuf,
        path: PathBuf, 
    }
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
        
            let peers: Vec<SocketAddrV4>;

            match utils::get_tracker(&t).await {
                core::result::Result::Ok(addresses) => {
                    peers = addresses;
                },
                Err(err) => {
                    panic!("{}", err);
                },
            };

            peers.iter().for_each(|p| println!("{p:?}"));
        }
        Command::Handshake { path, peer } => {
            eprintln!("{path:?} {peer:?}");
            let content = std::fs::read(path).context("Reading torrent file")?;
            let t: Torrent = serde_bencode::from_bytes(&content).context("parse torrent file")?;

            let mut tcp_peer = TcpStream::connect(peer)
                .await
                .context("Connecting to peer")?;

            let hs = Handshake::new(t.info.hash()?, b"00112233445566778899".to_owned());
            tcp_peer.write_all(&hs.to_bytes()).await?;

            let mut buf = [0; HANDSHAKE_LEN];
            tcp_peer.read_exact(&mut buf).await?;

            //eprintln!("{buf:?}");
            let hs_resp = Handshake::from_bytes(&buf)?;
            println!("Peer ID: {}", hex::encode(hs_resp.peer_id));
        }
        Command::DownloadPiece { output, path, piece_index } => {
            let content = std::fs::read(path).context("Reading torrent file")?;
            let t: Torrent = serde_bencode::from_bytes(&content).context("parse torrent file")?;

            let downloaded_piece: Vec<u8> = download_piece(&t, piece_index).await;

            // verify piece hash
            let a: usize = 20 * usize::try_from(piece_index).unwrap();
            let b: usize = 20 * usize::try_from(piece_index + 1).unwrap();
            let hash = |bytes: &[u8]| -> [u8; 20] {
                let mut hasher = Sha1::new();  
                hasher.update(bytes);
                hasher.finalize().into()
            };  

            let download_piece_hash = hash(&downloaded_piece);

            let piece_hash: Vec<_> = t.info.pieces.0
                .iter()
                .flat_map(|&array| array.iter().cloned().collect::<Vec<u8>>())
                .collect();
                
            assert_eq!(piece_hash[a..b], download_piece_hash);

            std::fs::write(output.clone(), downloaded_piece).unwrap();
            println!("Piece {} downloaded to {}.", piece_index, output.display());
        }
        Command::Download { output, path } => {
            let content = std::fs::read(path.clone()).context("Reading torrent file")?;
            let t: Torrent = serde_bencode::from_bytes(&content).context("parse torrent file")?;
            
            let torrent_arc = Arc::new(t);
            let downloaded_pieces: Vec<u8> = download_pieces(torrent_arc).await.context("problem dowload torrent").unwrap();
            std::fs::write(output.clone(), &downloaded_pieces)?;

            println!("Downloaded {:?} to {:?}", path, output);
        }
    }
    Ok(())
}
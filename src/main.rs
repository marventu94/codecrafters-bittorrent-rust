use anyhow::{Context, Ok};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
pub mod utils;

// Torrent
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
pub mod hashes;
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
}

fn main() -> anyhow::Result<()> {
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
use anyhow::{Context, Ok};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
pub mod utils;

// Torrent
use serde::Deserialize;
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
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct Torrent {
    announce: String,
    info: Info,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct Info {
    #[serde(rename = "piece length")]
    plength: usize,
    pieces: hashes::Hashes,
    #[serde(flatten)]
    keys: Keys,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum Keys {
    SingleFile { length: usize },
    MultiFile { files: File },
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct File {
    length: usize,
    path: Vec<String>,
}

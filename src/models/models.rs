use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use anyhow::anyhow;

mod hashes;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Info {
    name: String,
    #[serde(rename = "piece length")]
    pub plength: usize,
    pub pieces: hashes::Hashes,
    #[serde(flatten)]
    pub keys: Keys,
}

impl Info {
    pub fn hash(&self) -> anyhow::Result<[u8; 20]> {
        let info = serde_bencode::to_bytes(&self)?;
        let mut hasher = Sha1::new();
        hasher.update(&info);
        let hashed_info = hasher.finalize();
        hashed_info[..].try_into().map_err(|e| anyhow!("{}", e))
    }

    pub fn extract_length(&self) -> Option<usize> {
        match &self.keys {
            Keys::SingleFile { length } => Some(*length),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum Keys {
    SingleFile { length: usize },
    MultiFile { files: File },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct File {
    length: usize,
    path: Vec<String>,
}
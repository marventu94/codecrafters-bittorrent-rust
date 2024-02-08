use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use anyhow::anyhow;

mod hashes;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
}

const BLOCK_SIZE: usize = 16*1024;

impl Torrent {
    pub fn number_of_pieces(&self) -> u32 {
        let lenght = self.info.extract_length().unwrap() as u32;
        let piec_lenght = self.info.plength as u32;
    
        (lenght + piec_lenght - 1) / piec_lenght
    }

    pub fn piece_length(&self, piece_index: u32) -> u32 {
        let lenght = self.info.extract_length().unwrap() as u32;
        let piec_lenght = self.info.plength as u32;

        if piece_index == self.number_of_pieces() - 1 {
            lenght % piec_lenght
        } else {
            piec_lenght
        }
    }

    pub fn number_of_blocks(&self, piece_index: u32) -> u32 {
        let block_size_u32: u32 = BLOCK_SIZE.try_into().unwrap();
        // div_ceil not supported by Rust version of codecrafters.io:
        (self.piece_length(piece_index) + block_size_u32 - 1) / block_size_u32
    }    

    pub fn is_piece_hash_correct(&self, piece: &[u8], piece_index: u32) -> bool {
        let a: usize = 20 * usize::try_from(piece_index).unwrap();
        let b: usize = 20 * usize::try_from(piece_index + 1).unwrap();
        let hash = |bytes: &[u8]| -> [u8; 20] {
            let mut hasher = Sha1::new();
            hasher.update(bytes);
            hasher.finalize().into()
        };
        let piece_hash: Vec<_> = self.info.pieces.0
            .iter()
            .flat_map(|&array| array.iter().cloned().collect::<Vec<u8>>())
            .collect();

        piece_hash[a..b] == hash(&piece)
    }

    pub fn block_size(&self, block_index: u32, piece_index: u32) -> u32 {
        let block_size_u32 = BLOCK_SIZE.try_into().unwrap();
        let number_of_blocks = self.number_of_blocks(piece_index);
        let piece_length = self.piece_length(piece_index);
        if block_index == number_of_blocks - 1 && piece_length % block_size_u32 != 0 {
            piece_length % block_size_u32
        } else {
            block_size_u32
        }
    }
    
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
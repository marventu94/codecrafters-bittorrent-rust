use serde::de::{self, Visitor};
use serde::Deserialize;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Hashes(Vec<[u8; 20]>);

pub struct HashesVisitor;

impl<'de> Visitor<'de> for HashesVisitor {
    type Value = Hashes;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a byte string whose length is a multiple of 20")
    }
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() % 20 != 0 {
            return Err(E::custom(format!("length is {}", v.len())));
        }
        Ok(Hashes(
            v.chunks_exact(20)
                .map(|s| s.try_into().expect("guaranteed to be 20"))
                .collect(),
        ))
    }
}

impl<'de> Deserialize<'de> for Hashes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(HashesVisitor)
    }
}

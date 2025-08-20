use crate::{crypto::ristretto::*, AppSW};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub struct XelisPublicKey {
    pub compressed: CompressedRistretto,
}

impl XelisPublicKey {
    pub fn new(compressed: CompressedRistretto) -> Self {
        Self { compressed }
    }

    pub fn from_private_key(private_key: &[u8; 32]) -> Result<Self, AppSW> {
        let compressed = xelis_public_from_private(private_key)?;
        Ok(Self { compressed })
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

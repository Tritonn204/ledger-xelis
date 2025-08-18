use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::AppSW;
use ledger_device_sdk::ecc::CxError;

/// BIP32 path stored as an array of [`u32`].
#[derive(Default)]
pub struct Bip32Path(Vec<u32>);

impl AsRef<[u32]> for Bip32Path {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Bip32Path {
    type Error = AppSW;

    /// Constructs a [`Bip32Path`] from a given byte array.
    ///
    /// This method will return an error in the following cases:
    /// - the input array is empty,
    /// - the number of bytes in the input array is not a multiple of 4,
    ///
    /// # Arguments
    ///
    /// * `data` - Encoded BIP32 path. First byte is the length of the path, as encoded by ragger.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // Check data length
        if data.is_empty() // At least the length byte is required
            || (data[0] as usize * 4 != data.len() - 1)
        {
            return Err(AppSW::WrongApduLength);
        }

        Ok(Bip32Path(
            data[1..]
                .chunks(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
                .collect(),
        ))
    }
}

impl From<CxError> for AppSW {
    fn from(_e: CxError) -> Self {
        // pick the most appropriate app status
        AppSW::KeyDeriveFail
    }
}

pub fn to_hex(data: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    data.len() * 2
}

pub fn to_hex_string(data: &[u8]) -> String {
    let mut buf = vec![0u8; data.len() * 2];
    to_hex(data, &mut buf);
    // Safe because we know it's valid ASCII
    unsafe { String::from_utf8_unchecked(buf) }
}

pub fn to_hex_upper(data: &[u8], out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for (i, &byte) in data.iter().enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    data.len() * 2
}

pub fn to_hex_string_upper(data: &[u8]) -> String {
    let mut buf = vec![0u8; data.len() * 2];
    to_hex_upper(data, &mut buf);
    unsafe { String::from_utf8_unchecked(buf) }
}

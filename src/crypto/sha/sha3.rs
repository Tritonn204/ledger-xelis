use crate::AppSW;
use ledger_device_sdk::hash::sha3::Sha3_512;
use ledger_device_sdk::hash::HashInit;

/// SHA3-512 over `data`, returns 64-byte digest.
pub fn sha3_512(data: &[u8]) -> Result<[u8; 64], AppSW> {
    let mut digest = [0u8; 64];
    let mut hasher = Sha3_512::new();
    hasher.update(data).map_err(|_| AppSW::TxHashFail)?;
    hasher.finalize(&mut digest).map_err(|_| AppSW::TxHashFail)?;
    Ok(digest)
}
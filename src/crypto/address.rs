use crate::crypto::public_key::XelisPublicKey;
use crate::crypto::ristretto::CompressedRistretto;
use crate::AppSW;
use crate::utils::{to_hex_string, to_hex_string_upper};

const PREFIX_ADDRESS: &str = "xel";
const TESTNET_PREFIX_ADDRESS: &str = "xet";
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const SEPARATOR: u8 = b':';

use alloc::format;
use alloc::string::{String, ToString};

// Maximum address length: prefix(3) + separator(1) + data(~52) + checksum(6) = ~62
const MAX_ADDRESS_LEN: usize = 72;

pub struct Address {
    mainnet: bool,
    public_key: XelisPublicKey,
}

impl Address {
    pub fn new(mainnet: bool, public_key: XelisPublicKey) -> Self {
        Self {
            mainnet,
            public_key,
        }
    }

    pub fn to_bytes(&self) -> Result<([u8; MAX_ADDRESS_LEN], usize), AppSW> {
        let mut output = [0u8; MAX_ADDRESS_LEN];
        let mut pos = 0;

        // Add prefix
        let prefix = if self.mainnet {
            PREFIX_ADDRESS
        } else {
            TESTNET_PREFIX_ADDRESS
        };
        for &b in prefix.as_bytes() {
            output[pos] = b;
            pos += 1;
        }

        // Add separator
        output[pos] = SEPARATOR;
        pos += 1;

        // Get compressed public key (BE) and convert to LE for Xelis
        let le_bytes = self.public_key.compressed.to_le_bytes(); // This converts BE to LE
        let mut data_to_encode = [0u8; 33];
        data_to_encode[..32].copy_from_slice(&le_bytes);
        data_to_encode[32] = 0x00; // AddressType::Normal

        // Convert public key to 5-bit groups using LE bytes
        let mut bits_buf = [0u8; 64];
        let bits_len = convert_bits_fixed(&data_to_encode, 8, 5, true, &mut bits_buf)?;

        // Calculate checksum
        let checksum = create_checksum_fixed(prefix, &bits_buf[..bits_len]);

        // Encode data + checksum
        for i in 0..bits_len {
            if bits_buf[i] >= 32 {
                return Err(AppSW::Deny);
            }
            output[pos] = CHARSET[bits_buf[i] as usize];
            pos += 1;
        }

        for &cs in checksum.iter() {
            output[pos] = CHARSET[cs as usize];
            pos += 1;
        }

        Ok((output, pos))
    }
}

pub fn convert_bits_fixed(
    data: &[u8],
    from: u8,
    to: u8,
    pad: bool,
    output: &mut [u8],
) -> Result<usize, AppSW> {
    let mut acc: u32 = 0;
    let mut bits: u8 = 0;
    let mut idx = 0;
    let max_value = (1u32 << to) - 1;

    for &value in data {
        if (value as u32) >> from != 0 {
            return Err(AppSW::Deny);
        }

        acc = (acc << from) | (value as u32);
        bits += from;

        while bits >= to {
            bits -= to;
            if idx >= output.len() {
                return Err(AppSW::Deny);
            }
            output[idx] = ((acc >> bits) & max_value) as u8;
            idx += 1;
        }
    }

    if pad && bits > 0 {
        if idx >= output.len() {
            return Err(AppSW::Deny);
        }
        output[idx] = ((acc << (to - bits)) & max_value) as u8;
        idx += 1;
    }

    Ok(idx)
}

pub fn create_checksum_fixed(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut chk = 1u32;

    // Process HRP high bits
    for &b in hrp.as_bytes() {
        chk = polymod_step(chk, b >> 5);
    }

    // Separator
    chk = polymod_step(chk, 0);

    // Process HRP low bits
    for &b in hrp.as_bytes() {
        chk = polymod_step(chk, b & 31);
    }

    // Process data
    for &b in data {
        chk = polymod_step(chk, b);
    }

    // Process padding
    for _ in 0..6 {
        chk = polymod_step(chk, 0);
    }

    // Calculate checksum
    chk ^= 1;
    let mut result = [0u8; 6];
    for i in 0..6 {
        result[i] = ((chk >> (5 * (5 - i))) & 31) as u8;
    }

    result
}

#[inline]
fn polymod_step(chk: u32, value: u8) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let b = chk >> 25;
    let mut chk = ((chk & 0x1ffffff) << 5) ^ (value as u32);

    for i in 0..5 {
        if (b >> i) & 1 == 1 {
            chk ^= GEN[i];
        }
    }

    chk
}

pub fn format_address(pk_le: &[u8; 32], mainnet: bool, short: bool) -> Result<String, AppSW> {
    // Build XelisPublicKey from LE-compressed bytes
    let xpk = XelisPublicKey::new(CompressedRistretto::from_le_bytes(*pk_le));
    let addr = Address::new(mainnet, xpk);

    // Get full ASCII address bytes and turn into String
    let (buf, len) = addr.to_bytes()?;
    let full = core::str::from_utf8(&buf[..len])
        .map_err(|_| AppSW::AddrDisplayFail)?
        .to_string();

    if !short {
        return Ok(full);
    }
    Ok(shorten_addr_with_prefix(&full, 6, 6)) // keep 6 left and 6 right chars after "xel:" / "xet:"
}

pub fn format_address_safe(pk: &[u8; 32], mainnet: bool, short: bool, is_le: bool) -> String {
    // Validate first
    if !crate::crypto::ristretto::is_valid_compressed_ristretto(pk, is_le) {
        return format!(
            "[INVALID]0x{}...{}",
            to_hex_string(&pk[..6]),
            to_hex_string(&pk[26..])
        );
    }

    // Stack array for BE->LE conversion
    let mut tmp = *pk;
    if !is_le {
        tmp.reverse(); // In-place reverse for BE->LE
    }

    format_address(&tmp, mainnet, short).unwrap_or_else(|_| {
        format!(
            "[ERROR]0x{}...{}",
            to_hex_string(&tmp[..6]),
            to_hex_string(&tmp[26..])
        )
    })
}

// e.g. "xel:abc123...89def0"
fn shorten_addr_with_prefix(addr: &str, keep_left: usize, keep_right: usize) -> String {
    if let Some(colon) = addr.find(':') {
        let (hrp_with_sep, data) = addr.split_at(colon + 1);
        if data.len() <= keep_left + keep_right {
            return addr.to_string();
        }
        format!(
            "{}{}...{}",
            hrp_with_sep,
            &data[..keep_left],
            &data[data.len() - keep_right..]
        )
    } else {
        // Fallback if no ":" found
        let n = addr.len();
        if n <= keep_left + keep_right + 1 {
            addr.to_string()
        } else {
            format!("{}...{}", &addr[..keep_left], &addr[n - keep_right..])
        }
    }
}

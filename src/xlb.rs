//! XLB1 memo spec + parser (no hashing).
//! Host MUST send the memo TLV first; device displays *only* from this.
//! Signing is refused if no approved memo is in memory.

use alloc::vec::Vec;
use crate::AppSW;
use crate::tx_types::*;

pub const XLB1_MAGIC: &[u8; 4] = b"XLB1";
pub const XLB1_VERSION: u8 = 1;

// TLV tags (must match host):
pub const TAG_TX_TYPE:   u8 = 0x01;
pub const TAG_FEE:       u8 = 0x02;
pub const TAG_NONCE:     u8 = 0x03;
pub const TAG_OUT_COUNT: u8 = 0x10; // payload is the varint itself (no extra bytes)
pub const TAG_OUT_ITEM:  u8 = 0x20; // value = asset(32)|dest(32)|amount(8)|extra_len(varint)|preview_len(varint)|preview_bytes

#[derive(Clone, Debug)]
pub struct MemoOut {
    pub asset: [u8; 32],
    pub dest:  [u8; 32],
    pub amount: u64,
    pub extra_len: u64,
    pub preview: Vec<u8>, // first N bytes (may be empty)
}

#[derive(Clone, Debug)]
pub struct MemoPreview {
    pub tx_type: u8,
    pub fee: u64,
    pub nonce: u64,
    pub outs: Vec<MemoOut>,
}

/// Read unsigned LEB128 (u64).
fn read_leb128(buf: &[u8], mut off: usize) -> Result<(u64, usize), AppSW> {
    let mut val: u64 = 0;
    let mut shift = 0;
    loop {
        if off >= buf.len() { return Err(AppSW::TxParsingFail); }
        let b = buf[off]; off += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 { break; }
        shift += 7;
        if shift >= 64 { return Err(AppSW::TxParsingFail); }
    }
    Ok((val, off))
}

/// Parse memo TLV only (the host sends just this via APDU).
pub fn parse_memo_tlv(memo: &[u8]) -> Result<MemoPreview, AppSW> {
    let mut off = 0usize;
    let mut tx_type = 0u8;
    let mut fee = 0u64;
    let mut nonce = 0u64;
    let mut outs: Vec<MemoOut> = Vec::new();
    let mut expected_outs: Option<u64> = None;

    while off < memo.len() {
        let tag = memo[off]; off += 1;

        if tag == TAG_OUT_COUNT {
            let (n, noff) = read_leb128(memo, off)?; off = noff;
            expected_outs = Some(n);
            continue;
        }

        let (len, noff) = read_leb128(memo, off)?; off = noff;
        if off + (len as usize) > memo.len() { return Err(AppSW::TxParsingFail); }
        let val = &memo[off .. off + (len as usize)];
        off += len as usize;

        match tag {
            TAG_TX_TYPE => {
                if val.len() != 1 { return Err(AppSW::TxParsingFail); }
                tx_type = val[0];
            }
            TAG_FEE => {
                if val.len() != 8 { return Err(AppSW::TxParsingFail); }
                fee = u64::from_le_bytes(val.try_into().unwrap());
            }
            TAG_NONCE => {
                if val.len() != 8 { return Err(AppSW::TxParsingFail); }
                nonce = u64::from_le_bytes(val.try_into().unwrap());
            }
            TAG_OUT_ITEM => {
                // asset(32) | dest(32) | amount(8) | extra_len(varint) | preview_len(varint) | preview_bytes
                if val.len() < 32 + 32 + 8 { return Err(AppSW::TxParsingFail); }
                let mut p = 0usize;
                let mut asset = [0u8; 32]; asset.copy_from_slice(&val[p..p+32]); p += 32;
                let mut dest  = [0u8; 32]; dest .copy_from_slice(&val[p..p+32]); p += 32;
                let amount = u64::from_le_bytes(val[p..p+8].try_into().unwrap()); p += 8;
                let (extra_len, pn1) = read_leb128(val, p)?; p = pn1;
                let (preview_len, pn2) = read_leb128(val, p)?; p = pn2;
                if p + (preview_len as usize) > val.len() { return Err(AppSW::TxParsingFail); }
                let preview = val[p .. p + (preview_len as usize)].to_vec();

                outs.push(MemoOut { asset, dest, amount, extra_len, preview });
            }
            _ => {
                // Unknown tag: ignore (forward compatible)
            }
        }
    }

    if let Some(n) = expected_outs {
        if outs.len() as u64 != n { return Err(AppSW::TxParsingFail); }
    }

    Ok(MemoPreview { tx_type, fee, nonce, outs })
}

pub const TX_BURN: u8 = 0;
pub const TX_TRANSFER: u8 = 1;
pub const TX_MULTISIG: u8 = 2;
pub const TX_INVOKE_CONTRACT: u8 = 3;
pub const TX_DEPLOY_CONTRACT: u8 = 4;

/// Convert MemoPreview → ParsedTransaction for your existing UI.
pub fn memo_to_parsed_tx(m: &MemoPreview) -> ParsedTransaction {
    match m.tx_type {
        // Transfers
        TX_TRANSFER => {
            let transfers: Vec<ParsedTransfer> = m.outs.iter().map(|o| ParsedTransfer {
                asset: o.asset,
                recipient: o.dest,
                amount: o.amount,
                extra_data_present: o.extra_len > 0,
            }).collect();

            ParsedTransaction {
                version: 1,
                source: [0u8; 32],
                tx_type: XelisTxType::Transfer {
                    transfers,
                    total_count: m.outs.len() as u8,
                },
                fee: m.fee,
                nonce: m.nonce,
                total_size: 0,
            }
        }

        // Burn (fallback: take first out for display)
        TX_BURN => {
            let amount = m.outs.first().map(|o| o.amount).unwrap_or(0);
            let asset  = m.outs.first().map(|o| o.asset).unwrap_or([0u8; 32]);

            ParsedTransaction {
                version: 1,
                source: [0u8; 32],
                tx_type: XelisTxType::Burn(ParsedBurn { asset, amount }),
                fee: m.fee,
                nonce: m.nonce,
                total_size: 0,
            }
        }

        // Other types: extend later as you add memo support
        _ => ParsedTransaction {
            version: 1,
            source: [0u8; 32],
            tx_type: XelisTxType::Transfer { transfers: Vec::new(), total_count: 0 },
            fee: m.fee,
            nonce: m.nonce,
            total_size: 0,
        },
    }
}

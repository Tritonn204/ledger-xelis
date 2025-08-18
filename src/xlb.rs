//! XLB1 memo spec + parser (no hashing).
//! Host MUST send the memo TLV first; device displays *only* from this.
//! Signing is refused if no approved memo is in memory.

use crate::tx_types::*;
use crate::AppSW;
use alloc::vec::Vec;

pub const XLB1_MAGIC: &[u8; 4] = b"XLB1";
pub const XLB1_VERSION: u8 = 1;

// TLV tags (must match host):
pub const TAG_TX_TYPE: u8 = 0x01;
pub const TAG_FEE: u8 = 0x02;
pub const TAG_NONCE: u8 = 0x03;
pub const TAG_ASSET_TABLE: u8 = 0x04;  // New: asset table
pub const TAG_OUT_COUNT: u8 = 0x10;
pub const TAG_OUT_ITEM: u8 = 0x20;
pub const TAG_BURN: u8 = 0x30;

// Native asset is always index 0 (not stored in table)
pub const NATIVE_ASSET_INDEX: u8 = 0;
pub const NATIVE_ASSET: [u8; 32] = [0u8; 32];

use core::mem::MaybeUninit;

pub struct MemoWorkspace {
    pub asset_table: Vec<[u8; 32]>,
    pub outs: Vec<MemoOut>,
    pub burn: Option<MemoBurn>,
}

impl MemoWorkspace {
    #[inline] fn new() -> Self {
        Self { asset_table: Vec::new(), outs: Vec::new(), burn: None }
    }
    #[inline] pub fn clear(&mut self) {
        self.asset_table.clear();
        self.outs.clear();
        self.burn = None;
    }
}

static mut MEMO_WS: MaybeUninit<MemoWorkspace> = MaybeUninit::uninit();
static mut MEMO_WS_INIT: u8 = 0;

#[inline]
pub fn memo_ws_mut() -> &'static mut MemoWorkspace {
    // If interrupts could touch this, wrap the init block in a critical section.
    unsafe {
        if MEMO_WS_INIT == 0 {
            MEMO_WS.as_mut_ptr().write(MemoWorkspace::new());
            MEMO_WS_INIT = 1;
        }
        MEMO_WS.assume_init_mut()
    }
}

pub fn get_memo_asset(index: u8) -> [u8; 32] {
    unsafe {
        let ws = memo_ws_mut();
        if index == NATIVE_ASSET_INDEX {
            NATIVE_ASSET
        } else {
            // Index 1 maps to asset_table[0], 2 to [1], etc.
            let table_idx = (index as usize).saturating_sub(1);
            if table_idx < ws.asset_table.len() {
                ws.asset_table[table_idx]
            } else {
                // Shouldn't happen with valid memo
                NATIVE_ASSET
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct MemoOut {
    pub asset_index: u8,  // Index into asset table (0 = native)
    pub dest: [u8; 32],
    pub amount: u64,
    pub extra_len: u64,
    pub preview: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MemoPreview {
    pub tx_type: u8,
    pub fee: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug)]
pub struct MemoBurn {
    pub asset_index: u8,
    pub amount: u64,
}

/// Read unsigned LEB128 (u64).
fn read_leb128(buf: &[u8], mut off: usize) -> Result<(u64, usize), AppSW> {
    let mut val: u64 = 0;
    let mut shift = 0;
    loop {
        if off >= buf.len() {
            return Err(AppSW::TxParsingFail);
        }
        let b = buf[off];
        off += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(AppSW::TxParsingFail);
        }
    }
    Ok((val, off))
}

/// Parse memo TLV with asset table optimization
pub fn parse_memo_tlv(memo: &[u8]) -> Result<MemoPreview, AppSW> {
    let mut off = 0usize;
    let mut tx_type = 0u8;
    let mut fee = 0u64;
    let mut nonce = 0u64;
    let mut expected_outs: Option<u64> = None;

    let ws = memo_ws_mut();

    unsafe {
        ws.clear();
        while off < memo.len() {
            let tag = memo[off];
            off += 1;

            // Special handling for TAG_OUT_COUNT (no length field)
            if tag == TAG_OUT_COUNT {
                let (n, noff) = read_leb128(memo, off)?;
                off = noff;
                expected_outs = Some(n);
                continue;
            }

            let (len, noff) = read_leb128(memo, off)?;
            off = noff;
            if off + (len as usize) > memo.len() {
                return Err(AppSW::TxParsingFail);
            }
            let val = &memo[off..off + (len as usize)];
            off += len as usize;

            match tag {
                TAG_TX_TYPE => {
                    if val.len() != 1 {
                        return Err(AppSW::MemoInvalid);
                    }
                    tx_type = val[0];
                }
                TAG_FEE => {
                    if val.len() != 8 {
                        return Err(AppSW::MemoInvalid);
                    }
                    fee = u64::from_le_bytes(val.try_into().unwrap());
                }
                TAG_NONCE => {
                    if val.len() != 8 {
                        return Err(AppSW::MemoInvalid);
                    }
                    nonce = u64::from_le_bytes(val.try_into().unwrap());
                }
                TAG_ASSET_TABLE => {
                    // Parse asset table: count(varint) | asset1(32) | asset2(32) | ...
                    let mut p = 0usize;
                    let (asset_count, pn) = read_leb128(val, p)?;
                    p = pn;
                    
                    // Validate we have enough bytes for all assets
                    if p + (asset_count as usize * 32) > val.len() {
                        return Err(AppSW::MemoInvalid);
                    }
                    
                    // Read each asset
                    for _ in 0..asset_count {
                        let mut asset = [0u8; 32];
                        asset.copy_from_slice(&val[p..p + 32]);
                        p += 32;
                        ws.asset_table.push(asset);
                    }
                    
                    // Limit check (max 255 non-native assets since we use u8 index)
                    if ws.asset_table.len() > 255 {
                        return Err(AppSW::MemoInvalid);
                    }
                }
                TAG_OUT_ITEM => {
                    // Modified format: asset_index(1) | dest(32) | amount(8) | extra_len(varint) | preview_len(varint) | preview_bytes
                    if val.len() < 1 + 32 + 8 {
                        return Err(AppSW::MemoInvalid);
                    }
                    let mut p = 0usize;
                    
                    // Asset index (0 = native, 1+ = index into asset_table)
                    let asset_index = val[p];
                    p += 1;
                    
                    // Validate index
                    if asset_index > 0 && (asset_index as usize) > ws.asset_table.len() {
                        return Err(AppSW::MemoInvalid);
                    }
                    
                    let mut dest = [0u8; 32];
                    dest.copy_from_slice(&val[p..p + 32]);
                    p += 32;
                    
                    let amount = u64::from_le_bytes(val[p..p + 8].try_into().unwrap());
                    p += 8;
                    
                    let (extra_len, pn1) = read_leb128(val, p)?;
                    p = pn1;
                    let (preview_len, pn2) = read_leb128(val, p)?;
                    p = pn2;
                    
                    if p + (preview_len as usize) > val.len() {
                        return Err(AppSW::MemoInvalid);
                    }
                    let preview = val[p..p + (preview_len as usize)].to_vec();

                    ws.outs.push(MemoOut {
                        asset_index,
                        dest,
                        amount,
                        extra_len,
                        preview,
                    });
                },
                TAG_BURN => {
                    if val.len() < 1 + 8 { return Err(AppSW::MemoInvalid); }
                    let asset_index = val[0];
                    if asset_index > 0 && (asset_index as usize) > ws.asset_table.len() {
                        return Err(AppSW::MemoInvalid);
                    }
                    let amount = u64::from_le_bytes(val[1..9].try_into().unwrap());
                    let mut p = 9;
                    let (pv_len, pn) = read_leb128(val, p)?; p = pn;
                    if p + (pv_len as usize) > val.len() { return Err(AppSW::MemoInvalid); }
                    let preview = val[p..p + pv_len as usize].to_vec();

                    ws.burn = Some(MemoBurn { asset_index, amount });
                }
                _ => {
                    // Unknown tag: ignore (forward compatible)
                }
            }
        }

        if let Some(n) = expected_outs {
            if ws.outs.len() as u64 != n {
                return Err(AppSW::MemoInvalid);
            }
        }

        Ok(MemoPreview {
            tx_type,
            fee,
            nonce,
        })
    }
}

pub const TX_BURN: u8 = 0;
pub const TX_TRANSFER: u8 = 1;
pub const TX_MULTISIG: u8 = 2;
pub const TX_INVOKE_CONTRACT: u8 = 3;
pub const TX_DEPLOY_CONTRACT: u8 = 4;
use crate::{AppSW, xlb::MemoPreview};
use alloc::vec::Vec;

pub struct TxStreamParser {
    pub bytes_seen: usize,
    pub tx_version: u8,
    pub source_pubkey: [u8; 32],
    pub in_transfers: bool,
    pub transfer_count: u8,
    pub transfers_parsed: u8,
    pub pending_tail_skip: usize,
}

impl TxStreamParser {
    pub fn new() -> Self {
        Self {
            bytes_seen: 0,
            tx_version: 0,
            source_pubkey: [0u8; 32],
            in_transfers: false,
            transfer_count: 0,
            transfers_parsed: 0,
            pending_tail_skip: 0,
        }
    }
    
    pub fn reset(&mut self) {
        self.bytes_seen = 0;
        self.tx_version = 0;
        self.source_pubkey = [0u8; 32];
        self.in_transfers = false;
        self.transfer_count = 0;
        self.transfers_parsed = 0;
        self.pending_tail_skip = 0;
    }
    
    /// Parse transaction header from stream
    pub fn parse_header(
        &mut self,
        data: &[u8],
        memo: &MemoPreview,
    ) -> Result<usize, AppSW> {
        let mut offset = 0;
        
        // Version
        if self.bytes_seen == 0 && offset < data.len() {
            self.tx_version = data[offset];
            offset += 1;
            self.bytes_seen += 1;
        }
        
        // Source pubkey
        if self.bytes_seen >= 1 && self.bytes_seen < 33 {
            let needed = 33 - self.bytes_seen;
            let available = (data.len() - offset).min(needed);
            
            let start = self.bytes_seen - 1;
            self.source_pubkey[start..start + available]
                .copy_from_slice(&data[offset..offset + available]);
            
            offset += available;
            self.bytes_seen += available;
        }
        
        // TX type
        if self.bytes_seen == 33 && offset < data.len() {
            let tx_type = data[offset];
            offset += 1;
            self.bytes_seen += 1;
            
            // Verify matches memo
            if tx_type != memo.tx_type {
                return Err(AppSW::TxParsingFail);
            }
            
            self.in_transfers = tx_type == 1;
        }
        
        // Transfer count
        if self.bytes_seen == 34 && self.in_transfers && offset < data.len() {
            self.transfer_count = data[offset];
            offset += 1;
            self.bytes_seen += 1;
            
            if self.transfer_count != memo.outs.len() as u8 {
                return Err(AppSW::TxParsingFail);
            }
        } else if self.bytes_seen == 34 {
            self.bytes_seen = 35;
        }
        
        Ok(offset)
    }
    
    /// Extract commitment from transfer data
    pub fn extract_commitment_from_transfer(
        &mut self,
        data: &[u8],
    ) -> Result<(Option<[u8; 32]>, usize), AppSW> {
        let mut consumed = 0;
        
        // Handle pending tail skip
        if self.pending_tail_skip > 0 {
            let take = core::cmp::min(self.pending_tail_skip, data.len());
            self.pending_tail_skip -= take;
            return Ok((None, take));
        }
        
        // Need at least asset(32) + dest(32) + has_extra(1)
        if data.len() < 65 {
            return Ok((None, 0));
        }
        
        let mut off = 64; // Skip asset + destination
        
        // Handle extra data
        let has_extra = data[off];
        off += 1;
        
        if has_extra == 1 {
            let (len, used) = read_varint(&data[off..])?;
            off += used;
            if data.len() < off + len {
                return Ok((None, consumed));
            }
            off += len;
        }
        
        // Extract commitment
        if data.len() < off + 32 {
            return Ok((None, consumed));
        }
        
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&data[off..off + 32]);
        off += 32;
        
        // Calculate and handle tail
        let tail_len = transfer_tail_len_after_commit(self.tx_version);
        let have = data.len().saturating_sub(off);
        let take = core::cmp::min(tail_len, have);
        off += take;
        self.pending_tail_skip = tail_len - take;
        
        self.transfers_parsed += 1;
        consumed = off;
        
        Ok((Some(commitment), consumed))
    }
}

fn read_varint(data: &[u8]) -> Result<(usize, usize), AppSW> {
    let mut value = 0usize;
    let mut shift = 0;
    let mut consumed = 0;
    
    for &byte in data {
        if consumed >= 9 {
            return Err(AppSW::TxParsingFail);
        }
        
        value |= ((byte & 0x7F) as usize) << shift;
        consumed += 1;
        
        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }
        
        shift += 7;
    }
    
    Err(AppSW::TxParsingFail)
}

fn transfer_tail_len_after_commit(tx_version: u8) -> usize {
    32 + 32 + if tx_version >= 1 { 160 } else { 128 }
}
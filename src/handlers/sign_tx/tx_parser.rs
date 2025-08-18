use crate::{xlb::*, AppSW};
use alloc::vec::Vec;

pub struct TxStreamParser {
    pub bytes_seen: usize,
    pub tx_version: u8,
    pub source_pubkey: [u8; 32],
    pub in_transfers: bool,
    pub transfer_count: u8,
    pub transfers_parsed: u8,
    pub pending_tail_skip: usize,
    pub partial_buffer: [u8; 256],
    pub partial_len: usize,
    pub partial_type: PartialType,
    pub burn_parsed: bool,
}

pub const BURN_V1_LEN: [usize; 2] = [1062, 1382];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PartialType {
    None,
    ExtraLength,
    ExtraData(usize),
    Commitment,
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
            partial_buffer: [0u8; 256],
            partial_len: 0,
            partial_type: PartialType::None,
            burn_parsed: false,
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
        self.partial_buffer = [0u8; 256];
        self.partial_len = 0;
        self.partial_type = PartialType::None;
        self.burn_parsed = false;
    }

    /// Parse transaction header from stream
    pub fn parse_header(&mut self, data: &[u8], memo: &MemoPreview) -> Result<usize, AppSW> {
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

            match tx_type {
                TX_TRANSFER => {
                    self.in_transfers = true;
                }
                TX_BURN => {
                    self.bytes_seen = 35;
                    return Ok(offset);
                }
                _ => {
                    self.bytes_seen = 35;
                    return Ok(offset);
                }
            }
        }

        if self.bytes_seen == 34 && self.in_transfers && offset < data.len() {
            self.transfer_count = data[offset];
            offset += 1;
            self.bytes_seen += 1;

            unsafe {
                if self.transfer_count != memo_ws_mut().outs.len() as u8 {
                    return Err(AppSW::TxParsingFail);
                }
            }
        }

        Ok(offset)
    }

    pub fn parse_burn(&mut self, data: &[u8], memo: &MemoPreview) -> Result<usize, AppSW> {
        let mut offset = 0;

        // Burn payload is 40 bytes: asset(32) + amount(8)
        const BURN_PAYLOAD_SIZE: usize = 40;

        // Continue accumulating burn payload
        while self.partial_len < BURN_PAYLOAD_SIZE && offset < data.len() {
            self.partial_buffer[self.partial_len] = data[offset];
            self.partial_len += 1;
            offset += 1;
        }

        if self.partial_len == BURN_PAYLOAD_SIZE {
            let amount = u64::from_be_bytes(self.partial_buffer[32..40].try_into().unwrap());

            unsafe {
                if let Some(burn) = memo_ws_mut().burn.as_ref() {
                    if amount != burn.amount {
                        return Err(AppSW::TxParsingFail);
                    }
                } else {
                    return Err(AppSW::TxParsingFail);
                }
            }

            self.burn_parsed = true;
            self.partial_len = 0;
        }

        Ok(offset)
    }

    /// Extract commitment from transfer data
    pub fn extract_commitment_from_transfer(
        &mut self,
        data: &[u8],
    ) -> Result<(Option<[u8; 32]>, usize), AppSW> {
        let mut consumed = 0;
        let mut off = 0;

        // Handle pending tail skip first
        if self.pending_tail_skip > 0 {
            let take = core::cmp::min(self.pending_tail_skip, data.len());
            self.pending_tail_skip -= take;
            return Ok((None, take));
        }

        // Main processing loop
        loop {
            match self.partial_type {
                PartialType::None => {
                    // Starting fresh transfer - need asset(32) + dest(32) + has_extra(1) = 65 bytes
                    if self.partial_len < 65 {
                        let needed = 65 - self.partial_len;
                        let available = core::cmp::min(needed, data.len() - off);

                        self.partial_buffer[self.partial_len..self.partial_len + available]
                            .copy_from_slice(&data[off..off + available]);

                        off += available;
                        consumed += available;
                        self.partial_len += available;

                        if self.partial_len < 65 {
                            // Still need more data for header
                            return Ok((None, consumed));
                        }
                    }

                    // Now we have asset(32) + dest(32) + has_extra(1)
                    let has_extra = self.partial_buffer[64];
                    self.partial_len = 0; // Reset for next component

                    if has_extra == 1 {
                        // Move to reading extra length
                        self.partial_type = PartialType::ExtraLength;
                        // Continue in next iteration
                    } else {
                        // No extra data, move directly to commitment
                        self.partial_type = PartialType::Commitment;
                        // Continue in next iteration
                    }
                }

                PartialType::ExtraLength => {
                    // Continue reading varint for extra data length
                    let start_off = off;

                    for i in off..data.len() {
                        if self.partial_len >= 9 {
                            return Err(AppSW::TxParsingFail);
                        }

                        self.partial_buffer[self.partial_len] = data[i];
                        self.partial_len += 1;
                        off += 1;
                        consumed += 1;

                        if data[i] & 0x80 == 0 {
                            // Varint complete, parse it
                            let (extra_len, _) =
                                read_varint(&self.partial_buffer[..self.partial_len])?;
                            self.partial_len = 0; // Reset for next component

                            if extra_len > 0 {
                                self.partial_type = PartialType::ExtraData(extra_len);
                            } else {
                                // Zero-length extra, move to commitment
                                self.partial_type = PartialType::Commitment;
                            }
                            break;
                        }
                    }

                    if off == start_off || self.partial_type == PartialType::ExtraLength {
                        // No progress made or still reading varint
                        return Ok((None, consumed));
                    }
                    // Continue to next state
                }

                PartialType::ExtraData(total_len) => {
                    // Skip extra data (we don't validate it)
                    let remaining = total_len - self.partial_len;
                    let available = core::cmp::min(remaining, data.len() - off);

                    off += available;
                    consumed += available;
                    self.partial_len += available;

                    if self.partial_len >= total_len {
                        // Done with extra data, move to commitment
                        self.partial_type = PartialType::Commitment;
                        self.partial_len = 0; // Reset for commitment
                                              // Continue in next iteration
                    } else {
                        // Still skipping extra data
                        return Ok((None, consumed));
                    }
                }

                PartialType::Commitment => {
                    // Read the 32-byte commitment
                    let needed = 32 - self.partial_len;
                    let available = core::cmp::min(needed, data.len() - off);

                    self.partial_buffer[self.partial_len..self.partial_len + available]
                        .copy_from_slice(&data[off..off + available]);

                    off += available;
                    consumed += available;
                    self.partial_len += available;

                    if self.partial_len >= 32 {
                        // Commitment complete!
                        let mut commitment = [0u8; 32];
                        commitment.copy_from_slice(&self.partial_buffer[..32]);

                        // Reset state for next transfer
                        self.partial_type = PartialType::None;
                        self.partial_len = 0;

                        // Calculate and handle tail bytes to skip
                        let tail_len = transfer_tail_len_after_commit(self.tx_version);
                        let have = data.len().saturating_sub(off);
                        let skip_now = core::cmp::min(tail_len, have);
                        off += skip_now;
                        consumed += skip_now;
                        self.pending_tail_skip = tail_len - skip_now;

                        self.transfers_parsed += 1;

                        return Ok((Some(commitment), consumed));
                    } else {
                        // Still reading commitment
                        return Ok((None, consumed));
                    }
                }
            }

            // Check if we've consumed all available data
            if off >= data.len() {
                return Ok((None, consumed));
            }
        }
    }

    fn continue_varint(&mut self, data: &[u8]) -> Result<(Option<usize>, usize), AppSW> {
        let mut consumed = 0;

        for &byte in data {
            if self.partial_len >= 9 {
                return Err(AppSW::TxParsingFail);
            }

            self.partial_buffer[self.partial_len] = byte;
            self.partial_len += 1;
            consumed += 1;

            if byte & 0x80 == 0 {
                // Varint complete, parse it
                let (value, _) = read_varint(&self.partial_buffer[..self.partial_len])?;
                return Ok((Some(value), consumed));
            }
        }

        Ok((None, consumed))
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

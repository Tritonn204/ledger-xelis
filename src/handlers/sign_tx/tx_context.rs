use crate::{
    utils::Bip32Path,
    xlb::MemoPreview,
    crypto::commitment::CommitmentVerifier,
};
use alloc::vec::Vec;
use ledger_device_sdk::hash::sha3::Sha3_512;
use ledger_device_sdk::hash::HashInit;

pub struct TxContext {
    pub tx_hasher: Sha3_512,
    pub tx_hash: Option<[u8; 64]>,
    pub path: Bip32Path,
    pub total_size: usize,
    pub chunk_count: u16,

    // Memo/preview
    pub memo: Option<MemoPreview>,
    pub memo_buffer: Vec<u8>,
    pub memo_chunk_count: usize,
    pub preview_approved: bool,

    // Signing state
    pub sign_completed: bool,
    pub sign_succeeded: bool,

    // Blinders
    pub blinders: Vec<[u8; 32]>,
    
    // Commitment verification
    pub commitment_verifier: Option<CommitmentVerifier>,

    // Parsing state
    pub parse_state: TxParseState,
}

pub struct TxParseState {
    pub bytes_seen: usize,
    pub in_transfers: bool,
    pub transfer_count: u8,
    pub transfers_parsed: u8,
    pub tx_version: u8,
    pub source_pubkey: [u8; 32],
    pub pending_tail_skip: usize,
}

impl TxContext {
    pub fn new() -> Self {
        Self {
            tx_hasher: Sha3_512::new(),
            tx_hash: None,
            path: Default::default(),
            total_size: 0,
            chunk_count: 0,
            memo: None,
            memo_buffer: Vec::new(),
            memo_chunk_count: 0,
            preview_approved: false,
            sign_completed: false,
            sign_succeeded: false,
            blinders: Vec::new(),
            commitment_verifier: None,
            parse_state: TxParseState::new(),
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn init_commitment_verifier(&mut self, output_count: usize) {
        self.commitment_verifier = Some(CommitmentVerifier::new(output_count));
    }
}

impl TxParseState {
    pub fn new() -> Self {
        Self {
            bytes_seen: 0,
            in_transfers: false,
            transfer_count: 0,
            transfers_parsed: 0,
            tx_version: 0,
            source_pubkey: [0u8; 32],
            pending_tail_skip: 0,
        }
    }
}
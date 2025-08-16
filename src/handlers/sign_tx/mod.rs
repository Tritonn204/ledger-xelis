use crate::{
    app_ui::sign::ui_display_tx,
    crypto::{
        commitment::{verify_pedersen_commitment, CommitmentVerifier},
        ristretto::*,
        secure::*,
        signature::*,
    },
    utils::Bip32Path,
    xlb::{self, memo_to_parsed_tx, parse_memo_tlv, MemoPreview},
    AppSW,
};
use alloc::vec::Vec;
use ledger_device_sdk::hash::sha3::Sha3_512;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::io::Comm;

mod tx_parser;
pub use tx_parser::*;

const MAX_TRANSACTION_LEN: usize = 1_048_576;
const MAX_MEMO_SIZE: usize = 32 * 1024;
const MAX_CHUNKS: u16 = 4500;

pub struct TxContext {
    // Hashing
    tx_hasher: Sha3_512,
    tx_hash: Option<[u8; 64]>,

    // Path and metadata
    path: Bip32Path,
    total_size: usize,
    chunk_count: u16,

    // Memo handling
    memo: Option<MemoPreview>,
    memo_buffer: Vec<u8>,
    memo_chunk_count: usize,
    preview_approved: bool,

    // Signing state
    pub sign_completed: bool,
    pub sign_succeeded: bool,

    // Delegated components
    parser: TxStreamParser,
    verifier: CommitmentVerifier,
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
            parser: TxStreamParser::new(),
            verifier: CommitmentVerifier::new(),
        }
    }

    pub fn reset(&mut self) {
        self.tx_hasher = Sha3_512::new();
        self.tx_hash = None;
        self.path = Default::default();
        self.total_size = 0;
        self.chunk_count = 0;
        self.memo = None;
        self.memo_buffer.clear();
        self.memo_chunk_count = 0;
        self.preview_approved = false;
        self.sign_completed = false;
        self.sign_succeeded = false;
        self.parser.reset();
        self.verifier.reset();
    }
}

pub fn handler_load_memo(
    comm: &mut Comm,
    chunk: u8,
    more: bool,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if chunk == 0 {
        ctx.memo_buffer.clear();
        ctx.memo_chunk_count = 0;
        ctx.memo = None;
        ctx.preview_approved = false;
    }

    // Validate chunk sequence
    let expected_chunk = if ctx.memo_chunk_count == 0 {
        0
    } else {
        ((ctx.memo_chunk_count - 1) % 255) as u8 + 1
    };

    if chunk != expected_chunk {
        return Err(AppSW::TxParsingFail);
    }

    ctx.memo_chunk_count += 1;

    if ctx.memo_buffer.len() + data.len() > MAX_MEMO_SIZE {
        return Err(AppSW::TxWrongLength);
    }

    ctx.memo_buffer.extend_from_slice(data);

    if more {
        return Ok(());
    }

    // Parse and approve memo
    let preview = parse_memo_tlv(&ctx.memo_buffer)?;
    let parsed = memo_to_parsed_tx(&preview);
    ctx.memo_buffer.clear();

    if ui_display_tx(&parsed)? {
        ctx.memo = Some(preview);
        ctx.preview_approved = true;
        Ok(())
    } else {
        Err(AppSW::Deny)
    }
}

pub fn handler_send_blinders(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.len() % 32 != 0 {
        return Err(AppSW::WrongApduLength);
    }

    let apdu_header = comm.get_apdu_metadata();
    let p1 = apdu_header.p1;
    let p2 = apdu_header.p2;

    let mut blinders = Vec::new();

    if p1 != 0 {
        // Append to existing blinders (would need to store them in context)
        // For now, we'll just collect new ones
    }

    for chunk in data.chunks(32) {
        let mut blinder = [0u8; 32];
        blinder.copy_from_slice(chunk);
        blinder.reverse();
        blinders.push(blinder);
    }

    // Validate count if this is the last chunk
    if p2 & 0x80 != 0 {
        if let Some(memo) = &ctx.memo {
            let expected_outputs = match memo.tx_type {
                1 => memo.outs.len(),
                0 => 1,
                _ => 0,
            };

            if blinders.len() != expected_outputs {
                return Err(AppSW::TxParsingFail);
            }
        }
    }

    ctx.verifier.set_blinders(blinders);
    Ok(())
}

pub fn handler_sign_tx(
    comm: &mut Comm,
    chunk: u8,
    more: bool,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        return Err(AppSW::TxParsingFail);
    }

    if chunk == 0 {
        if !ctx.preview_approved {
            return Err(AppSW::MemoRequired);
        }

        ctx.sign_completed = false;
        ctx.sign_succeeded = false;
        ctx.tx_hasher = Sha3_512::new();
        ctx.tx_hash = None;
        ctx.total_size = 0;
        ctx.chunk_count = 0;
        ctx.path = data.try_into()?;
        ctx.parser.reset();

        // Initialize verification
        if let Some(memo) = &ctx.memo {
            if memo.tx_type == 0 || memo.tx_type == 1 {
                ctx.verifier.init_verification(memo.outs.len());
            }
        }

        return Ok(());
    }

    // Validate chunk sequence
    let expected_p1 = ((ctx.chunk_count % 255) as u8) + 1;
    if chunk != expected_p1 {
        return Err(AppSW::TxParsingFail);
    }
    ctx.chunk_count += 1;

    // Size checks
    ctx.total_size += data.len();
    if ctx.total_size > MAX_TRANSACTION_LEN {
        return Err(AppSW::TxWrongLength);
    }
    if ctx.chunk_count > MAX_CHUNKS {
        return Err(AppSW::TxParsingFail);
    }

    // Stream hash
    ctx.tx_hasher.update(data).map_err(|_| AppSW::TxHashFail)?;

    // Parse and verify
    parse_and_verify_stream(ctx, data)?;

    if !more {
        finalize_transaction(comm, ctx)?;
        ctx.sign_succeeded = true;
        ctx.sign_completed = true;
    }

    Ok(())
}

fn parse_and_verify_stream(ctx: &mut TxContext, data: &[u8]) -> Result<(), AppSW> {
    let memo = ctx.memo.as_ref().ok_or(AppSW::MemoInvalid)?;
    let mut offset = 0;

    // Parse header if needed
    if ctx.parser.bytes_seen < 35 {
        offset += ctx.parser.parse_header(&data[offset..], memo)?;
    }

    // Extract and verify commitments from transfers
    if ctx.parser.in_transfers {
        while ctx.parser.transfers_parsed < ctx.parser.transfer_count && offset < data.len() {
            let (commitment, consumed) = ctx
                .parser
                .extract_commitment_from_transfer(&data[offset..])?;

            if let Some(c) = commitment {
                let idx = (ctx.parser.transfers_parsed - 1) as usize;
                let amount = match memo.tx_type {
                    xlb::TX_TRANSFER => memo.outs[idx].amount,
                    xlb::TX_BURN => memo.outs[0].amount,
                    _ => return Err(AppSW::TxParsingFail),
                };

                ctx.verifier.verify_output(idx, &c, amount)?;
            }

            offset += consumed;
            ctx.parser.bytes_seen += consumed;
        }
    }

    Ok(())
}

fn finalize_transaction(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    // Final validation
    if let Some(memo) = &ctx.memo {
        if memo.tx_type == 0 || memo.tx_type == 1 {
            if !ctx.verifier.all_verified() {
                return Err(AppSW::InvalidCommitment);
            }
            if ctx.verifier.verified_count() != memo.outs.len() {
                return Err(AppSW::InvalidCommitment);
            }
        }
    }

    // Finalize hash
    let mut hash = [0u8; 64];
    ctx.tx_hasher
        .finalize(&mut hash)
        .map_err(|_| AppSW::TxSignFail)?;
    ctx.tx_hash = Some(hash);

    // Sign
    compute_signature_and_append(comm, ctx)
}

fn compute_signature_and_append(comm: &mut Comm, ctx: &TxContext) -> Result<(), AppSW> {
    let tx_hash = ctx.tx_hash.ok_or(AppSW::TxHashFail)?;

    with_derived_key(ctx.path.as_ref(), |private_key, _| {
        let pubkey = xelis_public_from_private(private_key.as_ref())?;
        let signature = schnorr_sign(private_key.as_ref(), &pubkey, &tx_hash)?;

        let sig_bytes = signature.to_le_bytes();
        comm.append(&[64u8]);
        comm.append(&sig_bytes);

        Ok(())
    })
}

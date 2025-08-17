mod tx_context;
mod tx_parser;
mod memo;

pub use tx_context::TxContext;
use tx_parser::TxStreamParser;

use crate::{
    AppSW,
    crypto::{signature::*, secure::*},
};
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::hash::HashInit;

const MAX_TRANSACTION_LEN: usize = 1_048_576;
const MAX_CHUNKS: u16 = 4500;

pub fn handler_load_memo(
    comm: &mut Comm,
    chunk: u8,
    more: bool,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    memo::load_memo(comm, chunk, more, ctx)
}

pub fn handler_send_blinders(
    comm: &mut Comm,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;
    
    if data.len() % 32 != 0 {
        return Err(AppSW::WrongApduLength);
    }
    
    let apdu_header = comm.get_apdu_metadata();
    let p1 = apdu_header.p1;
    let p2 = apdu_header.p2;

    if p1 == 0 && !ctx.blinders.is_empty() {
        ctx.blinders.clear();
    }
    
    for chunk in data.chunks(32) {
        let mut blinder = [0u8; 32];
        blinder.copy_from_slice(chunk);
        blinder.reverse();
        ctx.blinders.push(blinder);
    }
    
    // Final blinder chunk - validate count
    if p2 & 0x80 != 0 {
        if let Some(memo) = &ctx.memo {
            let expected_outputs = match memo.tx_type {
                crate::xlb::TX_TRANSFER => memo.outs.len(),
                crate::xlb::TX_BURN => 1,
                _ => 0,
            };
            
            if ctx.blinders.len() != expected_outputs {
                return Err(AppSW::TxParsingFail);
            }
        }
    }
    
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
        // Initialize signing
        if !ctx.preview_approved {
            return Err(AppSW::MemoRequired);
        }
        
        ctx.sign_completed = false;
        ctx.sign_succeeded = false;
        ctx.tx_hasher = ledger_device_sdk::hash::sha3::Sha3_512::new();
        ctx.tx_hash = None;
        ctx.total_size = 0;
        ctx.chunk_count = 0;
        ctx.path = data.try_into()?;
        ctx.parse_state = tx_context::TxParseState::new();
        
        // Verify blinders if needed
        if let Some(memo) = &ctx.memo {
            if matches!(memo.tx_type, crate::xlb::TX_TRANSFER | crate::xlb::TX_BURN) && ctx.blinders.is_empty() {
                return Err(AppSW::BlindersRequired);
            }
        }
        
        return Ok(());
    }

    // Validate chunk sequence
    let expected_chunk = ((ctx.chunk_count % 255) as u8).saturating_add(1).max(1);
    if chunk != expected_chunk {
        return Err(AppSW::TxParsingFail);
    }
    ctx.chunk_count = ctx.chunk_count.saturating_add(1);

    // Size limits
    ctx.total_size = ctx.total_size.saturating_add(data.len());
    if ctx.total_size > MAX_TRANSACTION_LEN {
        return Err(AppSW::TxWrongLength);
    }
    if ctx.chunk_count > MAX_CHUNKS {
        return Err(AppSW::TxParsingFail);
    }

    // Stream hash
    ctx.tx_hasher.update(data).map_err(|_| AppSW::TxHashFail)?;

    // Parse and validate
    TxStreamParser::parse_stream(ctx, data)?;

    if more {
        return Ok(());
    }
    
    // Final validation
    if let Some(memo) = &ctx.memo {
        if matches!(memo.tx_type, crate::xlb::TX_TRANSFER | crate::xlb::TX_BURN) {
            if let Some(verifier) = &ctx.commitment_verifier {
                if !verifier.all_verified() || verifier.verified_count() != memo.outs.len() {
                    return Err(AppSW::InvalidCommitment);
                }
            }
        }
    }
    
    finalize_transaction(comm, ctx)?;
    ctx.sign_succeeded = true;
    ctx.sign_completed = true;
    Ok(())
}

fn finalize_transaction(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    if !ctx.preview_approved || ctx.memo.is_none() {
        return Err(AppSW::MemoRequired);
    }

    // Finalize hash
    let mut hash = [0u8; 64];
    ctx.tx_hasher.finalize(&mut hash).map_err(|_| AppSW::TxHashFail)?;
    ctx.tx_hash = Some(hash);

    // Generate signature
    let tx_hash = ctx.tx_hash.ok_or(AppSW::TxHashFail)?;

    with_derived_key(ctx.path.as_ref(), |private_key, _chain_code| {
        let pubkey = xelis_public_from_private(private_key.as_ref())
            .map_err(|_| AppSW::KeyDeriveFail)?;

        let signature = schnorr_sign(private_key.as_ref(), &pubkey, &tx_hash)
            .map_err(|_| AppSW::TxSignFail)?;

        // Return signature in Xelis format: [s(32)][e(32)]
        let sig_bytes = signature.to_le_bytes();
        comm.append(&[64u8]);
        comm.append(&sig_bytes);
        
        Ok(())
    })
}
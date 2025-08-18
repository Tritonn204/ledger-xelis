use crate::{
    AppSW,
    xlb::*,
};
use tx_context::TxContext;
use ledger_device_sdk::io::Comm;

pub fn load_memo(
    comm: &mut Comm,
    chunk: u8,
    more: bool,
    ctx: &mut TxContext,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;
    
    // First chunk - reset state
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
    
    // Size check
    if ctx.memo_buffer.len() + data.len() > MAX_MEMO_SIZE {
        return Err(AppSW::TxWrongLength);
    }
    
    // Accumulate data
    ctx.memo_buffer.extend_from_slice(data);
    
    // If more chunks coming, just acknowledge
    if more {
        return Ok(());
    }
    
    // Last chunk - parse the complete memo
    let preview = parse_memo_tlv(&ctx.memo_buffer)?;
    let parsed = memo_to_parsed_tx(&preview);
    
    // Clear buffer to free memory
    ctx.memo_buffer.clear();
    
    // Show UI for approval
    if crate::app_ui::sign::ui_display_tx(&parsed)? {
        ctx.memo = Some(preview);
        ctx.preview_approved = true;
        
        // Initialize commitment verifier if needed
        let output_count = match preview.tx_type {
            crate::xlb::TX_TRANSFER | crate::xlb::TX_BURN => memo_ws_mut().outs.len(),
            _ => 0,
        };
        
        if output_count > 0 {
            ctx.init_commitment_verifier(output_count);
        }
        
        Ok(())
    } else {
        Err(AppSW::Deny)
    }
}
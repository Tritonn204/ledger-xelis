use crate::crypto::address::format_address_safe;
use crate::AppSW;
use crate::xlb::*;

use ledger_device_sdk::nbgl::{Field, NbglReview};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

use crate::utils::to_hex_string;

const FIELDS_PER_PAGE: usize = 10;

pub fn ui_display_memo_tx(preview: &MemoPreview) -> Result<bool, AppSW> {
    let ws = memo_ws_mut();
    let total_fields = 4 + ws.outs.len();
    let total_pages = (total_fields + FIELDS_PER_PAGE - 1) / FIELDS_PER_PAGE;
    
    for page in 0..total_pages {
        let start_idx = page * FIELDS_PER_PAGE;
        let end_idx = ((page + 1) * FIELDS_PER_PAGE).min(total_fields);
        
        let mut page_fields = Vec::with_capacity(end_idx - start_idx + 1);
        
        for i in start_idx..end_idx {
            let field = build_field_at_index(preview, i)?;
            page_fields.push(field);
        }
        
        let field_refs: Vec<Field> = page_fields.iter()
            .map(|(name, value)| Field {
                name: name.as_str(),
                value: value.as_str(),
            })
            .collect();
        
        let action_text = if page == total_pages - 1 { "Sign" } else { "Next" };
        
        let subtitle = format!("Section {}/{}", page + 1, total_pages);
        let review = NbglReview::new()
            .titles("Review Transaction", &subtitle, action_text)
            .light();
        
        let approved = review.show(&field_refs);
        
        if !approved {
            return Ok(false);
        }
    }
    
    Ok(true)
}

fn build_field_at_index(preview: &MemoPreview, index: usize) -> Result<(String, String), AppSW> {
    let ws = memo_ws_mut();
    
    if index == 0 {
        return Ok(("Type".to_string(), tx_type_name(preview.tx_type).to_string()));
    }
    
    if index == 1 {
        return Ok(("Outputs".to_string(), ws.outs.len().to_string()));
    }
    
    let output_start = 2;
    let output_end = output_start + ws.outs.len();
    
    if index >= output_start && index < output_end {
        let out_idx = index - output_start;
        let out = &ws.outs[out_idx];
        
        let label = format!("Output {}", out_idx + 1);
        let addr = format_address_safe(&out.dest, true, true, true);
        let asset = format_asset_from_index(out.asset_index);
        let amt = format_amount(out.amount);
        
        let value = format!("{addr}\n{asset}\n{amt}");
        return Ok((label, value));
    }
    
    if index == output_end {
        return Ok(("Fee".to_string(), format_amount(preview.fee)));
    }
    
    if index == output_end + 1 {
        return Ok(("Nonce".to_string(), preview.nonce.to_string()));
    }
    
    Err(AppSW::TxDisplayFail)
}

fn tx_type_name(tx_type: u8) -> &'static str {
    match tx_type {
        TX_TRANSFER => "Transfer",
        TX_BURN => "Burn",
        TX_MULTISIG => "MultiSig",
        TX_INVOKE_CONTRACT => "Contract Call",
        TX_DEPLOY_CONTRACT => "Deploy Contract",
        _ => "Unknown",
    }
}

fn format_asset_from_index(index: u8) -> String {
    let asset = get_memo_asset(index);
    if asset == NATIVE_ASSET {
        "XELIS".to_string()
    } else {
        format!(
            "{}...{}",
            to_hex_string(&asset[..4]),
            to_hex_string(&asset[28..])
        )
    }
}

fn format_amount(amount: u64) -> String {
    // XELIS uses 8 decimals
    let major = amount / 100_000_000;
    let minor = amount % 100_000_000;
    format!("{}.{:08}", major, minor)
}
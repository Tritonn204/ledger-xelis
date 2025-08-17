use crate::crypto::address::format_address_safe;
use crate::tx_types::{ParsedTransaction, ParsedTransfer, XelisTxType};
use crate::AppSW;
use ledger_device_sdk::nbgl::{Field, NbglReview};

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::utils::{to_hex_string, to_hex_string_upper};

pub fn ui_display_tx(tx: &ParsedTransaction) -> Result<bool, AppSW> {
    // Build all owned (name, value) pairs first, then borrow from them.
    let mut owned: Vec<(String, String)> = Vec::new();

    match &tx.tx_type {
        XelisTxType::Transfer {
            transfers,
            total_count,
        } => {
            owned.push(("Type".into(), "Transfer".into()));
            owned.push(("Outputs".into(), total_count.to_string()));

            // Show EVERY output with address * asset * amount [* extra]
            for (i, t) in transfers.iter().enumerate() {
                let label = format!("Output {}", i + 1);
                let addr = format_address_safe(&t.recipient, true, true, true);
                let asset = format_asset(&t.asset);
                let amt = format_amount(t.amount);

                let mut value = format!("{addr}\n{asset}\n{amt}");
                owned.push((label, value));
            }
        }

        XelisTxType::Burn(burn) => {
            owned.push(("Type".into(), "Burn".into()));
            owned.push(("Asset".into(), format_asset(&burn.asset)));
            owned.push(("Amount".into(), format_amount(burn.amount)));
        }

        XelisTxType::MultiSig(ms) => {
            owned.push(("Type".into(), "MultiSig".into()));
            owned.push(("Threshold".into(), ms.threshold.to_string()));
            owned.push(("Participants".into(), ms.participants_count.to_string()));
        }

        XelisTxType::InvokeContract(c) => {
            owned.push(("Type".into(), "Contract Call".into()));
            owned.push(("Contract".into(), format_hash(&c.contract)));
            owned.push(("Max Gas".into(), c.max_gas.to_string()));
            owned.push(("Deposits".into(), c.deposits_count.to_string()));
        }

        XelisTxType::DeployContract {
            has_constructor,
            max_gas,
        } => {
            owned.push(("Type".into(), "Deploy Contract".into()));
            owned.push((
                "Constructor".into(),
                if *has_constructor {
                    "Yes".into()
                } else {
                    "No".into()
                },
            ));
            owned.push(("Max Gas".into(), max_gas.to_string()));
        }
    }

    // Fee + Nonce last
    owned.push(("Fee".into(), format_amount(tx.fee)));
    owned.push(("Nonce".into(), tx.nonce.to_string()));

    // Now build the NBGL fields borrowing from `owned`
    let mut fields: Vec<Field> = Vec::with_capacity(owned.len());
    for (name, value) in &owned {
        fields.push(Field {
            name: name.as_str(),
            value: value.as_str(),
        });
    }

    let review = NbglReview::new()
        .titles("Review transaction", "", "Sign")
        .light();

    Ok(review.show(&fields))
}

fn format_asset(asset: &[u8; 32]) -> String {
    const XELIS_ASSET: [u8; 32] = [0; 32]; // replace if main asset differs
    if *asset == XELIS_ASSET {
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

fn format_hash(hash: &[u8; 32]) -> String {
    format!(
        "{}...{}",
        to_hex_string_upper(&hash[..6]),
        to_hex_string_upper(&hash[26..])
    )
}

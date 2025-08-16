use crate::app_ui::address::ui_display_pk;
use crate::{AppSW, utils::Bip32Path};
use crate::crypto::{ristretto::*, public_key::*, address::*};
use crate::crypto::secure::with_derived_key;
use ledger_device_sdk::io::Comm;

pub fn handler_get_public_key(comm: &mut Comm, display: bool) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;
    let path: Bip32Path = data.try_into()?;

    let (pk_le, _) = with_derived_key(path.as_ref(), |scalar, chain_code| {
        let pk_comp = xelis_public_from_private(scalar.as_ref())
            .map_err(|_| AppSW::KeyDeriveFail)?;
        
        Ok((pk_comp.to_le_bytes(), *chain_code.as_ref()))
    })?;

    if display {
        let is_mainnet = true;
        let xpk = XelisPublicKey::new(CompressedRistretto::from_le_bytes(pk_le));
        let addr = Address::new(is_mainnet, xpk);
        let (addr_bytes, len) = addr.to_bytes().map_err(|_| AppSW::TxSignFail)?;
        if !ui_display_pk(&addr_bytes[..len])? {
            return Err(AppSW::Deny);
        }
    }

    comm.append(&[32u8]);
    comm.append(&pk_le);

    Ok(())
}
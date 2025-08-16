use crate::AppSW;
use alloc::format;
use core::str;
use core::convert::TryInto;

use include_gif::include_gif;
use ledger_device_sdk::nbgl::{NbglAddressReview, NbglGlyph};
use crate::alloc::string::ToString;

const DISPLAY_ADDR_BYTES_LEN: usize = 20; // hex fallback (last 20 bytes)

pub fn ui_display_pk(addr: &[u8]) -> Result<bool, AppSW> {
    // Load glyphs
    #[cfg(any(target_os = "stax", target_os = "flex"))]
    const FERRIS: NbglGlyph = NbglGlyph::from_include(include_gif!("xelis_64x64.gif", NBGL));
    #[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
    const FERRIS: NbglGlyph = NbglGlyph::from_include(include_gif!("xelis_15x15.gif", NBGL));

    let fixed: [u8; 32] = addr
        .try_into()
        .map_err(|_| AppSW::AddrDisplayFail)?;
    // Use shared formatting logic
    let display_str = crate::crypto::address::format_address_safe(&fixed, true, false, true);

    Ok(NbglAddressReview::new()
        .glyph(&FERRIS)
        .verify_str("Verify XELIS address")
        .show(&display_str))
}
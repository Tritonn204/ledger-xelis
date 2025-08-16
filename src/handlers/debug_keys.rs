use crate::{crypto::{*, ristretto::*, public_key::*, address::*, secure::*}, AppSW};
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::ecc::{bip32_derive, CurvesId};

pub fn handler_debug_keys(comm: &mut Comm) -> Result<(), AppSW> {
    let apdu_header = comm.get_apdu_metadata();
    
    match apdu_header.p2 {
        0 => {
            comm.append(&[0x2C]);
            test_bip32_derivation(comm)?;
            test_public_key_derivation(comm)?;
            test_address_generation(comm)?;
            Ok(())
        }
        1 => {
            handler_get_generator_full(comm)
        }
        _ => Err(AppSW::WrongP1P2)
    }
}

fn test_bip32_derivation(comm: &mut Comm) -> Result<(), AppSW> {
    comm.append(&[0xBD]);
    
    // Test WITHOUT scalar_reduce
    comm.append(&[0xD4]); // New test marker
    let simple_path = [0x8000002C, 0x80000000, 0x80000000, 0x00000000, 0x00000000];
    
    let mut key_buffer = [0u8; 64];
    let mut chain_code = [0u8; 32];
    
    match bip32_derive(CurvesId::Ed25519, &simple_path, &mut key_buffer, Some(&mut chain_code)) {
        Ok(()) => {
            comm.append(&[0x01]); // BIP32 succeeded
            comm.append(&key_buffer[..8]);
            
            let mut scalar_be = [0u8; 32];
            scalar_be.copy_from_slice(&key_buffer[..32]);
            
            // Ed25519 clamping (in LE before reversal)
            scalar_be[0] &= 248;
            scalar_be[31] &= 63;
            scalar_be[31] |= 64;
            
            scalar_be.reverse(); // LE → BE
            
            comm.append(&[0x01]); // Skip scalar_reduce test
            comm.append(&scalar_be[..8]);
            
            // Test xelis_public_from_private WITHOUT scalar_reduce
            // (it should call scalar_invert internally which may do the reduction)
            match xelis_public_from_private(&scalar_be) {
                Ok(pk_comp) => {
                    comm.append(&[0x01]); // Success!
                    let pk_le = pk_comp.to_le_bytes();
                    comm.append(&pk_le[..8]);
                }
                Err(_) => {
                    comm.append(&[0x00]); // Failed
                }
            }
        }
        Err(_) => {
            comm.append(&[0x00]); // BIP32 failed
        }
    }
    
    comm.append(&[0xDD]);
    Ok(())
}

fn test_public_key_derivation(comm: &mut Comm) -> Result<(), AppSW> {
    comm.append(&[0xF6]); // Full key pair verification
    
    // Test 1: Private key = 1
    comm.append(&[0xA1]);
    let mut private_1 = [0u8; 32];
    private_1[31] = 1; // 1 in BE
    
    match xelis_public_from_private(&private_1) {
        Ok(public_compressed) => {
            comm.append(&[0x01]); // Success
            
            // Expected (LE): 8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134
            let expected_le = [
                0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
                0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
                0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
                0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34
            ];
            
            let public_le = public_compressed.to_le_bytes();
            let matches = public_le == expected_le;
            comm.append(&[if matches { 0x01 } else { 0x00 }]);
        }
        Err(_) => comm.append(&[0x00]),
    }
    
    // Test 2: Private key = 2  
    comm.append(&[0xA2]);
    let mut private_2 = [0u8; 32];
    private_2[31] = 2; // 2 in BE
    
    match xelis_public_from_private(&private_2) {
        Ok(public_compressed) => {
            comm.append(&[0x01]); // Success
            
            // Expected (LE): f05bc1df2831717c2992d85b57e0cf3d123fd6c254257de5f784be369747b249
            let expected_le = [
                0xf0, 0x5b, 0xc1, 0xdf, 0x28, 0x31, 0x71, 0x7c,
                0x29, 0x92, 0xd8, 0x5b, 0x57, 0xe0, 0xcf, 0x3d,
                0x12, 0x3f, 0xd6, 0xc2, 0x54, 0x25, 0x7d, 0xe5,
                0xf7, 0x84, 0xbe, 0x36, 0x97, 0x47, 0xb2, 0x49
            ];
            
            let public_le = public_compressed.to_le_bytes();
            let matches = public_le == expected_le;
            comm.append(&[if matches { 0x01 } else { 0x00 }]);
        }
        Err(_) => comm.append(&[0x00]),
    }
    
    // Test 3: Private key = [0x01; 32]
    comm.append(&[0xA3]);
    let private_3_le = [0x01u8; 32];
    let private_3_be = CompressedRistretto::from_le_bytes(private_3_le).0;
    
    match xelis_public_from_private(&private_3_be) {
        Ok(public_compressed) => {
            comm.append(&[0x01]); // Success
            
            // Expected (LE): 02064b89dc89f5c353cf2077800e24fb83300d48b1af4a3926f1fe0a1864cf06
            let expected_le = [
                0x02, 0x06, 0x4b, 0x89, 0xdc, 0x89, 0xf5, 0xc3,
                0x53, 0xcf, 0x20, 0x77, 0x80, 0x0e, 0x24, 0xfb,
                0x83, 0x30, 0x0d, 0x48, 0xb1, 0xaf, 0x4a, 0x39,
                0x26, 0xf1, 0xfe, 0x0a, 0x18, 0x64, 0xcf, 0x06
            ];
            
            let public_le = public_compressed.to_le_bytes();
            let matches = public_le == expected_le;
            comm.append(&[if matches { 0x01 } else { 0x00 }]);
        }
        Err(_) => comm.append(&[0x00]),
    }

    comm.append(&[0xA4]);
    let private_4_be = [0xffu8; 32]; // All 0xFF in BE

    match xelis_public_from_private(&private_4_be) {
        Ok(public_compressed) => {
            comm.append(&[0x01]); // Success
            
            // Expected (LE): f6decfbf9efabc8aa59452aa570cb84eed7fcfca7daea58a93b93444400a7a73
            let expected_le = [
                0xf6, 0xde, 0xcf, 0xbf, 0x9e, 0xfa, 0xbc, 0x8a,
                0xa5, 0x94, 0x52, 0xaa, 0x57, 0x0c, 0xb8, 0x4e,
                0xed, 0x7f, 0xcf, 0xca, 0x7d, 0xae, 0xa5, 0x8a,
                0x93, 0xb9, 0x34, 0x44, 0x40, 0x0a, 0x7a, 0x73
            ];
            
            let public_le = public_compressed.to_le_bytes();
            let matches = public_le == expected_le;
            comm.append(&[if matches { 0x01 } else { 0x00 }]);
        }
        Err(_) => comm.append(&[0x00]),
    }
        
    // Summary: all three should pass
    comm.append(&[0xAA]); // End marker
    
    Ok(())
}

fn test_address_generation(comm: &mut Comm) -> Result<(), AppSW> {
    comm.append(&[0xAD]); // Address generation test marker
    
    // Test 1: Private key = 1
    comm.append(&[0xB1]);
    let public_1_bytes = [
        0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
        0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
        0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
        0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34
    ];
    let expected_mainnet_1 = "xel:3jfypdzk48ndcewrw7ssfrt5t722prxm0azvhntmgme5qjy8zy6qqckgjqg";
    let expected_testnet_1 = "xet:3jfypdzk48ndcewrw7ssfrt5t722prxm0azvhntmgme5qjy8zy6qqq9zzvk";
    
    test_single_address(comm, &public_1_bytes, true, expected_mainnet_1)?;
    test_single_address(comm, &public_1_bytes, false, expected_testnet_1)?;
    
    // Test 2: Private key = 2
    comm.append(&[0xB2]);
    let public_2_bytes = [
        0xf0, 0x5b, 0xc1, 0xdf, 0x28, 0x31, 0x71, 0x7c,
        0x29, 0x92, 0xd8, 0x5b, 0x57, 0xe0, 0xcf, 0x3d,
        0x12, 0x3f, 0xd6, 0xc2, 0x54, 0x25, 0x7d, 0xe5,
        0xf7, 0x84, 0xbe, 0x36, 0x97, 0x47, 0xb2, 0x49
    ];
    let expected_mainnet_2 = "xel:7pdurhegx9chc2vjmpd40cx085frl4kz2sjhme0hsjlrd968kfysq434xga";
    let expected_testnet_2 = "xet:7pdurhegx9chc2vjmpd40cx085frl4kz2sjhme0hsjlrd968kfysqdzlkyr";
    
    test_single_address(comm, &public_2_bytes, true, expected_mainnet_2)?;
    test_single_address(comm, &public_2_bytes, false, expected_testnet_2)?;
    
    // Test 3: Private key = [0x01; 32]
    comm.append(&[0xB3]);
    let public_3_bytes = [
        0x02, 0x06, 0x4b, 0x89, 0xdc, 0x89, 0xf5, 0xc3,
        0x53, 0xcf, 0x20, 0x77, 0x80, 0x0e, 0x24, 0xfb,
        0x83, 0x30, 0x0d, 0x48, 0xb1, 0xaf, 0x4a, 0x39,
        0x26, 0xf1, 0xfe, 0x0a, 0x18, 0x64, 0xcf, 0x06
    ];
    let expected_mainnet_3 = "xel:qgryhzwu386ux570ypmcqr3ylwpnqr2gkxh55wfx78lq5xryeurqqza63mr";
    let expected_testnet_3 = "xet:qgryhzwu386ux570ypmcqr3ylwpnqr2gkxh55wfx78lq5xryeurqq6wspha";
    
    test_single_address(comm, &public_3_bytes, true, expected_mainnet_3)?;
    test_single_address(comm, &public_3_bytes, false, expected_testnet_3)?;
    
    comm.append(&[0xB4]);
    let public_4_bytes = [
        0xf6, 0xde, 0xcf, 0xbf, 0x9e, 0xfa, 0xbc, 0x8a,
        0xa5, 0x94, 0x52, 0xaa, 0x57, 0x0c, 0xb8, 0x4e,
        0xed, 0x7f, 0xcf, 0xca, 0x7d, 0xae, 0xa5, 0x8a,
        0x93, 0xb9, 0x34, 0x44, 0x40, 0x0a, 0x7a, 0x73
    ];
    let expected_mainnet_4 = "xel:7m0vl0u7l27g4fv52249wr9cfmkhln720kh2tz5nhy6ygsq20fesqn2udfx";
    let expected_testnet_4 = "xet:7m0vl0u7l27g4fv52249wr9cfmkhln720kh2tz5nhy6ygsq20fesqteka9c";
    
    test_single_address(comm, &public_4_bytes, true, expected_mainnet_4)?;
    test_single_address(comm, &public_4_bytes, false, expected_testnet_4)?;

    comm.append(&[0xAF]); // End marker
    Ok(())
}

fn test_single_address(
    comm: &mut Comm,
    public_key_le: &[u8; 32],
    mainnet: bool,
    expected: &str
) -> Result<(), AppSW> {
    let public_key = XelisPublicKey::new(CompressedRistretto::from_le_bytes(*public_key_le));
    let addr = Address::new(mainnet, public_key);
    
    match addr.to_bytes() {
        Ok((addr_bytes, len)) => {
            let matches = &addr_bytes[..len] == expected.as_bytes();
            comm.append(&[if matches { 0x01 } else { 0x00 }]);
            
            // If it doesn't match, send some debug info
            if !matches {
                comm.append(&[len as u8]);
                comm.append(&[expected.len() as u8]);
                // Send first few bytes of actual vs expected
                comm.append(&addr_bytes[..8.min(len)]);
            }
        }
        Err(_) => {
            comm.append(&[0xFF]); // Failed
        }
    }
    
    Ok(())
}

pub fn handler_get_generator_full(comm: &mut Comm) -> Result<(), AppSW> {
    pub const XELIS_H_COMPRESSED: [u8; 32] = [
        0x34, 0x11, 0x87, 0x48, 0x40, 0xf3, 0x46, 0x7b,
        0xcd, 0xcb, 0x44, 0x7f, 0xdb, 0x8c, 0xa0, 0x94,
        0x5f, 0x74, 0x8d, 0x04, 0xa1, 0x77, 0xc3, 0x65,
        0xdc, 0xe6, 0xa9, 0x56, 0xb4, 0x40, 0x92, 0x8c
    ];

    pub const XELIS_G_COMPRESSED: [u8; 32] = [
        0x76, 0x2d, 0x8d, 0xe0, 0x45, 0x59, 0xa6, 0xb6, 
        0x8d, 0xdd, 0x82, 0xa5, 0x6a, 0x0b, 0xe3, 0x58, 
        0x5f, 0x51, 0x00, 0xc5, 0x61, 0xa9, 0x84, 0xa8, 
        0x71, 0x4e, 0xbc, 0x6a, 0x0a, 0xae, 0xf2, 0xe2
    ];

    let apdu_header = comm.get_apdu_metadata();
    
    let generator = match apdu_header.p1 {
        0 => {
            let g_compressed = CompressedRistretto::from_be_bytes(XELIS_G_COMPRESSED);
            g_compressed.decompress().map_err(|_| AppSW::ParamError)?
        }
        1 => {
            let h_compressed = CompressedRistretto::from_be_bytes(XELIS_H_COMPRESSED);
            h_compressed.decompress().map_err(|_| AppSW::ParamError)?
        }
        _ => return Err(AppSW::ParamError),
    };
    
    // Return all 128 bytes: x||y||z||t
    comm.append(&generator.x);
    comm.append(&generator.y);
    comm.append(&generator.z);
    comm.append(&generator.t);
    
    Ok(())
}

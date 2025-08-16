#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use crate::AppSW;
use core::{mem::MaybeUninit, ptr};

// Pull the ABI-correct types & functions from the sys crate (tiny, no std)
use ledger_secure_sdk_sys::{
    cx_hash_no_throw, cx_keccak_init_no_throw, cx_sha3_init_no_throw, cx_sha3_t, CX_LAST,
    CX_NO_REINIT,
};

/// SHA3-512 over `data`, returns 64-byte digest.
pub fn sha3_512(data: &[u8]) -> Result<[u8; 64], AppSW> {
    unsafe {
        // 1) init context for SHA3-512
        let mut ctx = MaybeUninit::<cx_sha3_t>::uninit();
        let err = cx_sha3_init_no_throw(ctx.as_mut_ptr(), 512);
        if err != 0 {
            return Err(AppSW::TxHashFail);
        }
        let mut ctx = ctx.assume_init();

        // 2) update with data
        let err = cx_hash_no_throw(
            (&mut ctx as *mut cx_sha3_t).cast(),
            0, // mode: update
            data.as_ptr(),
            data.len(),
            ptr::null_mut(),
            0,
        );
        if err != 0 {
            return Err(AppSW::TxHashFail);
        }

        // 3) finalize into 64-byte output
        let mut out = [0u8; 64];
        let err = cx_hash_no_throw(
            (&mut ctx as *mut cx_sha3_t).cast(),
            CX_LAST | CX_NO_REINIT, // finalize, don't reinit
            ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
        );
        if err != 0 {
            return Err(AppSW::TxHashFail);
        }
        Ok(out)
    }
}

/// (Optional) Keccak-512 (legacy padding) if you need it.
pub fn keccak_512(data: &[u8]) -> Result<[u8; 64], AppSW> {
    unsafe {
        let mut ctx = MaybeUninit::<cx_sha3_t>::uninit();
        let err = cx_keccak_init_no_throw(ctx.as_mut_ptr(), 512);
        if err != 0 {
            return Err(AppSW::TxHashFail);
        }
        let mut ctx = ctx.assume_init();

        let err = cx_hash_no_throw(
            (&mut ctx as *mut cx_sha3_t).cast(),
            0,
            data.as_ptr(),
            data.len(),
            core::ptr::null_mut(),
            0,
        );
        if err != 0 {
            return Err(AppSW::TxHashFail);
        }

        let mut out = [0u8; 64];
        let err = cx_hash_no_throw(
            (&mut ctx as *mut cx_sha3_t).cast(),
            CX_LAST | CX_NO_REINIT,
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
        );
        if err != 0 {
            return Err(AppSW::TxHashFail);
        }
        Ok(out)
    }
}

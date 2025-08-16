use crate::crypto::{ristretto::*, scalar, scalar::*, sha::sha3_512, *};
use crate::cx::*;
use crate::AppSW;
use alloc::vec;

/// XELIS signature: s || e (both 32-byte big-endian)
pub const SIGNATURE_SIZE: usize = 64;

pub struct XelisSignature {
    pub s: [u8; 32], // BE
    pub e: [u8; 32], // BE
}

impl XelisSignature {
    pub fn to_be_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..32].copy_from_slice(&self.s);
        out[32..].copy_from_slice(&self.e);
        out
    }

    pub fn to_le_bytes(&self) -> [u8; 64] {
        let mut s = self.s;
        let mut e = self.e;
        s.reverse();
        e.reverse();

        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&s);
        out[32..].copy_from_slice(&e);
        out
    }
}

/// Compute the XELIS challenge scalar e using **wide** reduction:
///   e = reduce_wide( SHA3-512( A_compressed || message || R_compressed ) )
pub fn xelis_challenge_from_hash(
    a_comp: &CompressedRistretto,
    message: &[u8],
    r_comp: &CompressedRistretto,
) -> Result<[u8; 32], AppSW> {
    // Concat: A || msg || R  (all as bytes actually hashed by XELIS)
    let a_le = a_comp.to_le_bytes();
    let r_le = r_comp.to_le_bytes();

    let mut buf = vec![0u8; 32 + message.len() + 32];
    buf[..32].copy_from_slice(&a_le);
    buf[32..32 + message.len()].copy_from_slice(message);
    buf[32 + message.len()..].copy_from_slice(&r_le);

    // SHA3-512
    let wide = sha3_512(&buf)?; // 64 bytes

    // Wide reduction mod L -> 32B BE
    // IMPORTANT: do a *wide* mod, not "take 32 then reduce".
    let mut be = [0u8; 32];
    reduce_mod_l_wide_le_to_be(&wide, &mut be)?;
    Ok(be)
}

/// Interpret `wide_le` as a little-endian 512-bit integer, reduce mod L,
/// return a 32-byte **big-endian** scalar.
fn reduce_mod_l_wide_le_to_be(wide_le: &[u8; 64], out_be: &mut [u8; 32]) -> Result<(), AppSW> {
    // cx expects BE; convert LE->BE
    let mut tmp = *wide_le;
    tmp.reverse();

    let rc = unsafe { cx_math_modm_no_throw(tmp.as_mut_ptr() as *mut u8, 64, L.as_ptr(), 32) };
    if rc != 0 {
        return Err(AppSW::CryptoError);
    }

    // Result is BE, right-aligned in `tmp`
    out_be.copy_from_slice(&tmp[64 - 32..]);
    Ok(())
}

/// XELIS Schnorr sign:
///   A = x^{-1}·H   (public key already provided as compressed)
///   R = k·H
///   e = H512(A||msg||R) (wide mod L)
///   s = x^{-1}·e + k
pub fn schnorr_sign(
    private_key_be: &[u8; 32],               // BE
    pubkey_compressed: &CompressedRistretto, // A = x^{-1}·H (compressed)
    message_hash: &[u8], // what you actually commit to (e.g., first 32 of SHA3-512(tx))
) -> Result<XelisSignature, AppSW> {
    // 0) Sanity: secret != 0
    if scalar::is_zero(private_key_be) {
        return Err(AppSW::TxSignFail);
    }

    // 1) Deterministic nonce k (keep what you had, but ensure nonzero + reduced)
    let mut k_be = det_nonce_be(private_key_be, message_hash)?;
    if scalar::is_zero(&k_be) {
        return Err(AppSW::TxSignFail);
    }

    // 2) R = k·H
    let r_point = scalar_mult_ristretto(&k_be, &XELIS_H_POINT).map_err(|_| AppSW::TxSignFail)?;
    let r_comp = r_point.compress().map_err(|_| AppSW::TxSignFail)?;

    // 3) e = reduce_wide( SHA3-512( A || msg || R ) )
    let e_be = xelis_challenge_from_hash(&pubkey_compressed, &message_hash[..], &r_comp)?;

    // 4) s = x^{-1}·e + k
    let inv_sk_be = scalar_invert(&private_key_be)?; // returns [u8;32]
    let mut e_over_sk_be = [0u8; 32];
    scalar_multiply(&mut e_over_sk_be, &e_be, &inv_sk_be).map_err(|_| AppSW::TxSignFail)?;
    let mut s_be = [0u8; 32];
    scalar_add(&mut s_be, &k_be, &e_over_sk_be).map_err(|_| AppSW::TxSignFail)?;

    Ok(XelisSignature { s: s_be, e: e_be })
}

/// Deterministic nonce k (simple, reproducible): H(private || msg) → wide reduce → BE
pub fn det_nonce_be(sk_be: &[u8; 32], msg: &[u8]) -> Result<[u8; 32], AppSW> {
    let mut inbuf = vec![0u8; 32 + msg.len()];
    inbuf[..32].copy_from_slice(sk_be);
    inbuf[32..].copy_from_slice(msg);
    let wide = sha3_512(&inbuf)?; // 64 bytes

    let mut k_be = [0u8; 32];
    reduce_mod_l_wide_le_to_be(&wide, &mut k_be)?;
    if scalar::is_zero(&k_be) {
        // extremely unlikely, but reject anyway
        return Err(AppSW::TxSignFail);
    }
    Ok(k_be)
}

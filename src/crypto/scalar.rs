use crate::alloc::string::ToString;
use crate::crypto::{ristretto::CompressedRistretto, *};
use crate::{cx::*, AppSW};
use alloc::format;
use alloc::string::String;
use ledger_device_sdk::ecc::CxError;
use ledger_device_sdk::random;

/// Check if a scalar is zero
pub fn is_zero(scalar: &[u8; 32]) -> bool {
    scalar.iter().all(|&b| b == 0)
}

/// Reduce a scalar modulo the group order L
/// Input and output are in big-endian format
pub fn scalar_reduce(scalar: &mut [u8; 32]) -> Result<(), CxError> {
    unsafe {
        let result = cx_math_modm_no_throw(scalar.as_mut_ptr(), 32, L.as_ptr(), 32);
        if result != 0 {
            return Err(CxError::InvalidParameter);
        }
    }
    Ok(())
}

/// Compute scalar inversion: s^(-1) = s^(l-2) mod l
/// Input and output are in big-endian format
pub fn scalar_invert(scalar: &[u8; 32]) -> Result<[u8; 32], AppSW> {
    if is_zero(scalar) {
        return Err(AppSW::KeyDeriveFail);
    }

    let mut result = [0u8; 32];

    unsafe {
        let res = cx_math_powm_no_throw(
            result.as_mut_ptr(),
            scalar.as_ptr(),
            L_MINUS_2.as_ptr(),
            32,
            L.as_ptr(),
            32,
        );
        if res != 0 {
            return Err(AppSW::KeyDeriveFail);
        }
    }

    Ok(result)
}

/// Add two scalars modulo L: result = (a + b) mod L
/// All inputs and outputs are in big-endian format
pub fn scalar_add(result: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32]) -> Result<(), CxError> {
    unsafe {
        let res =
            cx_math_addm_no_throw(result.as_mut_ptr(), a.as_ptr(), b.as_ptr(), L.as_ptr(), 32);
        if res != 0 {
            return Err(CxError::InvalidParameter);
        }
    }
    Ok(())
}

/// Subtract two scalars modulo L: result = (a - b) mod L
/// All inputs and outputs are in big-endian format
pub fn scalar_subtract(result: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32]) -> Result<(), CxError> {
    unsafe {
        let res =
            cx_math_subm_no_throw(result.as_mut_ptr(), a.as_ptr(), b.as_ptr(), L.as_ptr(), 32);
        if res != 0 {
            return Err(CxError::InvalidParameter);
        }
    }
    Ok(())
}

/// Multiply two scalars modulo L: result = (a * b) mod L
/// All inputs and outputs are in big-endian format
pub fn scalar_multiply(result: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32]) -> Result<(), CxError> {
    unsafe {
        let res =
            cx_math_multm_no_throw(result.as_mut_ptr(), a.as_ptr(), b.as_ptr(), L.as_ptr(), 32);
        if res != 0 {
            return Err(CxError::InvalidParameter);
        }
    }
    Ok(())
}

/// Generate a random scalar using the secure element's TRNG
/// Output is in big-endian format and reduced modulo L
pub fn scalar_random(result: &mut [u8; 32]) -> Result<(), AppSW> {
    random::rand_bytes(result);
    scalar_reduce(result).map_err(|_| AppSW::CryptoError)?;

    Ok(())
}

/// Create a scalar from a 64-byte hash (like SHA3-512 output)
/// Uses "from_bytes_mod_order_wide" approach
/// Input is 64 bytes, output is 32 bytes in big-endian format
pub fn scalar_from_bytes_wide(bytes: &[u8; 64]) -> Result<[u8; 32], AppSW> {
    // Take the 64-byte input and reduce it modulo L
    // We'll use the CX library's modular reduction with extended precision

    let mut wide = *bytes; // [u8; 64]
    let rc = unsafe {
        cx_math_modm_no_throw(
            wide.as_mut_ptr(),
            wide.len(), // 64
            L.as_ptr(),
            L.len(), // 32
        )
    };
    if rc != 0 {
        return Err(AppSW::CryptoError);
    }

    // CX stores the BE remainder “in place”. For BE, the least-significant
    // (i.e., remainder) lives in the *last* len_m bytes.
    let mut out = [0u8; 32];
    out.copy_from_slice(&wide[wide.len() - L.len()..]); // last 32 bytes
    Ok(out)
}

/// Create a deterministic scalar from seed material (for nonce generation)
/// Uses HMAC-like construction for deterministic randomness
pub fn scalar_deterministic(
    result: &mut [u8; 32],
    key: &[u8; 32],
    message: &[u8],
) -> Result<(), AppSW> {
    // Simple deterministic approach: Hash(key || message)
    // In production, you'd want proper HMAC or RFC6979

    let mut combined = alloc::vec::Vec::new();
    combined.extend_from_slice(key);
    combined.extend_from_slice(message);

    // Hash with SHA3-512 for wide reduction
    let hash = crate::crypto::sha::sha3_512(&combined)?;

    // Reduce to scalar
    *result = scalar_from_bytes_wide(&hash)?;

    Ok(())
}

/// Convert a 32-byte array to scalar, ensuring it's reduced modulo L
/// Input and output are both in big-endian format
pub fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<[u8; 32], AppSW> {
    let mut result = *bytes;
    scalar_reduce(&mut result).map_err(|_| AppSW::CryptoError)?;
    Ok(result)
}

/// Check if a scalar is valid (non-zero and less than L)
pub fn scalar_is_valid(scalar: &[u8; 32]) -> bool {
    // Check if non-zero
    if is_zero(scalar) {
        return false;
    }

    // Check if less than L (this is a simplified check)
    // In big-endian, we can compare byte by byte from left to right
    for i in 0..32 {
        if scalar[i] < L[i] {
            return true;
        } else if scalar[i] > L[i] {
            return false;
        }
        // If equal, continue to next byte
    }

    // If we get here, scalar == L, which is invalid
    false
}

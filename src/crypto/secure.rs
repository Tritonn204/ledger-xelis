//! Security utilities for handling sensitive cryptographic material
//!
//! This module provides RAII wrappers and helper functions to ensure
//! sensitive data like private keys are properly zeroed after use.

use crate::AppSW;
use core::sync::atomic::{compiler_fence, Ordering};
use ledger_device_sdk::ecc::{bip32_derive, CurvesId};

/// RAII wrapper for sensitive data that automatically wipes on drop
///
/// This ensures that sensitive cryptographic material is always
/// cleared from memory when it goes out of scope, preventing
/// potential data leaks.
pub struct SensitiveBytes<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> SensitiveBytes<N> {
    /// Create a new zeroed sensitive buffer
    pub fn new() -> Self {
        Self { data: [0u8; N] }
    }

    /// Get mutable access to the underlying array
    pub fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }

    /// Get read-only access to the underlying array
    pub fn as_ref(&self) -> &[u8; N] {
        &self.data
    }

    /// Copy data from a slice, truncating if necessary
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        let len = core::cmp::min(N, src.len());
        self.data[..len].copy_from_slice(&src[..len]);
    }

    /// Reverse the bytes in-place (useful for endianness conversion)
    pub fn reverse(&mut self) {
        self.data.reverse();
    }
}

impl<const N: usize> Default for SensitiveBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Drop for SensitiveBytes<N> {
    /// Securely wipe the data when dropped
    #[inline(never)]
    fn drop(&mut self) {
        secure_wipe(&mut self.data);
    }
}

/// Securely wipe a byte array using volatile writes
///
/// This ensures the compiler cannot optimize away the zeroing
/// operation, which is critical for security.
#[inline(never)]
pub fn secure_wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Single core: always derive (64B key, 32B chain code), expose 32B scalar view.
/// Kept non-inlined to avoid code bloat from monomorphization.
#[inline(never)]
pub fn with_derived_core<F, R>(path: &[u32], f: F) -> Result<R, AppSW>
where
    F: FnOnce(&mut SensitiveBytes<32>, &mut SensitiveBytes<32>) -> Result<R, AppSW>,
{
    // OS requires 64-byte buffer for Secp256k1/Secp256r1/Ed25519
    let mut key_buffer = SensitiveBytes::<64>::new();
    let mut chain_code = SensitiveBytes::<32>::new();

    bip32_derive(
        CurvesId::Ed25519,
        path,
        key_buffer.as_mut(),
        Some(chain_code.as_mut()),
    )
    .map_err(|_| AppSW::KeyDeriveFail)?;

    let mut scalar = SensitiveBytes::<32>::new();
    scalar.as_mut().copy_from_slice(&key_buffer.as_ref()[..32]);

    f(&mut scalar, &mut chain_code)
}

/// Convenience: caller only needs the scalar.
/// This is a thin shim around `with_derived_core`.
#[inline]
pub fn with_derived_key<F, R>(path: &[u32], f: F) -> Result<R, AppSW>
where
    F: FnOnce(&mut SensitiveBytes<32>) -> Result<R, AppSW>,
{
    with_derived_core(path, |scalar, _cc| f(scalar))
}

/// Convenience: caller needs scalar + chain code.
/// Alias to the core function to keep old call-sites working.
#[inline]
pub fn with_derived_key_chain<F, R>(path: &[u32], f: F) -> Result<R, AppSW>
where
    F: FnOnce(&mut SensitiveBytes<32>, &mut SensitiveBytes<32>) -> Result<R, AppSW>,
{
    with_derived_core(path, f)
}

/// Constant-time comparison of byte arrays
///
/// This prevents timing attacks by ensuring comparison time
/// is independent of where differences occur.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

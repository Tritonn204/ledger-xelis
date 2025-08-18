use crate::{
    crypto::{ristretto::*, scalar::*, *},
    AppSW,
};
use alloc::vec;
use alloc::vec::Vec;

/// Verify a Pedersen commitment: C = v·G + r·H
/// where v is the amount and r is the blinding factor
pub fn verify_pedersen_commitment(
    commitment: &[u8; 32],
    amount: u64,
    blinder: &[u8; 32],
) -> Result<(), AppSW> {
    // Prepare amount as scalar (big-endian, 32 bytes)
    let mut amount_scalar = [0u8; 32];
    amount_scalar[24..32].copy_from_slice(&amount.to_be_bytes());

    // Compute v·G
    let vg = scalar_mult_ristretto(&amount_scalar, &XELIS_G_POINT)?;

    // Compute r·H
    let rh = scalar_mult_ristretto(blinder, &XELIS_H_POINT)?;

    // Compute C = v·G + r·H
    let computed = edwards_add(&vg, &rh)?;
    let computed_bytes = computed.compress()?.to_le_bytes();

    // Verify commitment matches
    if computed_bytes != *commitment {
        return Err(AppSW::InvalidCommitment);
    }

    Ok(())
}

/// State for tracking commitment verification across multiple outputs
pub struct CommitmentVerifier {
    blinders: Vec<[u8; 32]>,
    outputs_verified: Vec<bool>,
    commitments_verified: usize,
}

impl CommitmentVerifier {
    pub fn new() -> Self {
        Self {
            blinders: Vec::new(),
            outputs_verified: Vec::new(),
            commitments_verified: 0,
        }
    }

    pub fn reset(&mut self) {
        self.blinders.clear();
        self.outputs_verified.clear();
        self.commitments_verified = 0;
    }

    /// Initialize blinders for a new set (clears existing)
    pub fn init_blinders(&mut self) {
        self.blinders.clear();
    }

    /// Add a single blinder (for chunked receiving)
    pub fn add_blinder(&mut self, blinder: [u8; 32]) {
        self.blinders.push(blinder);
    }

    /// Add multiple blinders at once
    pub fn add_blinders(&mut self, blinders: &[[u8; 32]]) {
        self.blinders.extend_from_slice(blinders);
    }

    /// Get the current count of blinders
    pub fn blinder_count(&self) -> usize {
        self.blinders.len()
    }

    /// Get a reference to the blinders (for validation)
    pub fn blinders(&self) -> &[[u8; 32]] {
        &self.blinders
    }

    /// Legacy method - kept for compatibility but prefer init_blinders + add_blinder
    pub fn set_blinders(&mut self, blinders: Vec<[u8; 32]>) {
        self.blinders = blinders;
    }

    pub fn init_verification(&mut self, output_count: usize) {
        self.outputs_verified = vec![false; output_count];
        self.commitments_verified = 0;
    }

    pub fn verify_output(
        &mut self,
        idx: usize,
        commitment: &[u8; 32],
        amount: u64,
    ) -> Result<(), AppSW> {
        // Bounds check
        if idx >= self.outputs_verified.len() || idx >= self.blinders.len() {
            return Err(AppSW::TxParsingFail);
        }

        // Verify the commitment
        verify_pedersen_commitment(commitment, amount, &self.blinders[idx])?;

        // Mark as verified
        self.outputs_verified[idx] = true;
        self.commitments_verified += 1;

        Ok(())
    }

    pub fn all_verified(&self) -> bool {
        self.outputs_verified.iter().all(|&v| v)
    }

    pub fn verified_count(&self) -> usize {
        self.commitments_verified
    }
}
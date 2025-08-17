use super::*;
use crate::cx::*;
use crate::AppSW;
use ledger_device_sdk::ecc::{CurvesId, CxError};
use scalar::*;

pub const ED25519_SCALAR_BYTES: usize = 32;

pub type Fe25519 = [u8; ED25519_SCALAR_BYTES];

pub const ED25519_FIELD_SIZE: Fe25519 = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
];

pub const ED25519_POW225: Fe25519 = [
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
];

pub const FE25519_SQRTM1: Fe25519 = [
    0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b, 0x2b, 0x4d, 0x00, 0x99, 0x3d, 0xfb, 0xd7, 0xa7,
    0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f, 0xe4, 0x78, 0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0,
];

pub const ED25519_INVSQRTAMD: Fe25519 = [
    0x78, 0x6c, 0x89, 0x05, 0xcf, 0xaf, 0xfc, 0xa2, 0x16, 0xc2, 0x7b, 0x91, 0xfe, 0x01, 0xd8, 0x40,
    0x9d, 0x2f, 0x16, 0x17, 0x5a, 0x41, 0x72, 0xbe, 0x99, 0xc8, 0xfd, 0xaa, 0x80, 0x5d, 0x40, 0xea,
];

pub const EDWARDS_D: Fe25519 = [
    // -121665/121666 mod p (BE)
    0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73, 0x8c, 0xc7, 0x40, 0x79, 0x77, 0x79, 0xe8, 0x98,
    0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41, 0xd8, 0xab, 0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3,
];

pub const FE25519_ONE: Fe25519 = {
    let mut a = [0u8; 32];
    a[31] = 1;
    a
};

pub const IDENTITY_POINT: RistrettoPoint = {
    RistrettoPoint {
        x: [0; 32],
        y: FE25519_ONE,
        z: FE25519_ONE,
        t: [0; 32],
    }
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CompressedRistretto(pub [u8; 32]); // Stored in BE internally

impl CompressedRistretto {
    /// Create from little-endian bytes (external format)
    pub fn from_le_bytes(bytes: [u8; 32]) -> Self {
        let mut be_bytes = bytes;
        be_bytes.reverse();
        CompressedRistretto(be_bytes)
    }

    /// Create from big-endian bytes (internal format)
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        CompressedRistretto(bytes)
    }

    /// Export to little-endian bytes (external format)
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut le_bytes = self.0;
        le_bytes.reverse();
        le_bytes
    }

    /// Export to big-endian bytes (internal format)
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RistrettoPoint {
    pub x: Fe25519, // BE internally
    pub y: Fe25519, // BE internally
    pub z: Fe25519, // BE internally
    pub t: Fe25519, // BE internally
}

#[inline(always)]
pub fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

#[inline(always)]
unsafe fn field_op(
    op: unsafe extern "C" fn(*mut u8, *const u8, *const u8, *const u8, usize) -> u32,
    out: &mut Fe25519,
    a: &Fe25519,
    b: &Fe25519,
) -> Result<(), CxError> {
    if op(
        out.as_mut_ptr(),
        a.as_ptr(),
        b.as_ptr(),
        ED25519_FIELD_SIZE.as_ptr(),
        32,
    ) != 0
    {
        Err(CxError::InvalidParameter)
    } else {
        Ok(())
    }
}

pub fn fe25519_mul(h: &mut Fe25519, f: &Fe25519, g: &Fe25519) -> Result<(), CxError> {
    unsafe { field_op(cx_math_multm_no_throw, h, f, g) }
}

pub fn fe25519_add(h: &mut Fe25519, f: &Fe25519, g: &Fe25519) -> Result<(), CxError> {
    unsafe { field_op(cx_math_addm_no_throw, h, f, g) }
}

pub fn fe25519_sub(h: &mut Fe25519, f: &Fe25519, g: &Fe25519) -> Result<(), CxError> {
    unsafe { field_op(cx_math_subm_no_throw, h, f, g) }
}

pub fn fe25519_pow22523(out: &mut Fe25519, z: &Fe25519) -> Result<(), CxError> {
    unsafe {
        let result = cx_math_powm_no_throw(
            out.as_mut_ptr(),
            z.as_ptr(),
            ED25519_POW225.as_ptr(),
            ED25519_SCALAR_BYTES,
            ED25519_FIELD_SIZE.as_ptr(),
            ED25519_SCALAR_BYTES,
        );
        if result != 0 {
            Err(CxError::InvalidParameter)
        } else {
            Ok(())
        }
    }
}

#[inline(always)]
pub fn fe25519_sq(h: &mut Fe25519, f: &Fe25519) -> Result<(), CxError> {
    fe25519_mul(h, f, f)
}

#[inline(always)]
fn fe25519_is_zero(f: &Fe25519) -> bool {
    is_zero(f)
}

#[inline(always)]
pub fn fe25519_is_negative(f: &Fe25519) -> bool {
    f[31] & 1 == 1
}

pub fn fe25519_neg(h: &mut Fe25519, f: &Fe25519) -> Result<(), CxError> {
    unsafe {
        let result = cx_math_subm_no_throw(
            h.as_mut_ptr(),
            ED25519_FIELD_SIZE.as_ptr(),
            f.as_ptr(),
            ED25519_FIELD_SIZE.as_ptr(),
            32,
        );
        if result != 0 {
            Err(CxError::InvalidParameter)
        } else {
            Ok(())
        }
    }
}

pub fn fe25519_conditional_negate(f: &mut Fe25519, negate: bool) -> Result<(), CxError> {
    let mask = (negate as u8).wrapping_neg();
    let mut neg = [0u8; 32];
    fe25519_neg(&mut neg, f)?;

    for i in 0..32 {
        f[i] = (f[i] & !mask) | (neg[i] & mask);
    }
    Ok(())
}

// Ristretto decompression
#[cfg(debug_assertions)]
impl CompressedRistretto {
    #[inline(never)]
    pub fn decompress(&self) -> Result<RistrettoPoint, AppSW> {
        // self.0 is already in BE
        let mut s = self.0;

        // Check that s is non-negative (high bit clear in BE is at index 0)
        if s[0] & 0x80 != 0 {
            return Err(AppSW::InvalidCompressedRistretto);
        }

        // Clear high bits for field element
        s[0] &= 0x7f;

        // Step 2: Compute the decompressed point
        let one = FE25519_ONE;
        let mut ss = [0u8; 32];
        let mut u1 = [0u8; 32];
        let mut u2 = [0u8; 32];
        let mut u2_sqr = [0u8; 32];
        let mut v = [0u8; 32];
        let mut i = [0u8; 32];
        let mut dx = [0u8; 32];
        let mut dy = [0u8; 32];
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        let mut t = [0u8; 32];
        let mut temp = [0u8; 32];

        // ss = s^2
        fe25519_sq(&mut ss, &s).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // u1 = 1 - ss
        fe25519_sub(&mut u1, &one, &ss).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // u2 = 1 + ss
        fe25519_add(&mut u2, &one, &ss).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // u2_sqr = u2^2
        fe25519_sq(&mut u2_sqr, &u2).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // v = -d * u1^2 - u2^2
        let mut u1_sqr = [0u8; 32];
        fe25519_sq(&mut u1_sqr, &u1).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        let mut neg_d = [0u8; 32];
        fe25519_neg(&mut neg_d, &EDWARDS_D).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        fe25519_mul(&mut temp, &neg_d, &u1_sqr).map_err(|_| AppSW::InvalidCompressedRistretto)?;
        fe25519_sub(&mut v, &temp, &u2_sqr).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // Compute inverse square root
        let mut v_u2_sqr = [0u8; 32];
        fe25519_mul(&mut v_u2_sqr, &v, &u2_sqr).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        let (ok, _was_square) = ristretto255_sqrt_ratio_m1(&mut i, &one, &v_u2_sqr)
            .map_err(|_| AppSW::InvalidCompressedRistretto)?;

        if !ok {
            return Err(AppSW::InvalidCompressedRistretto);
        }

        // dx = i * u2
        fe25519_mul(&mut dx, &i, &u2).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // dy = i * dx * v
        fe25519_mul(&mut temp, &i, &dx).map_err(|_| AppSW::InvalidCompressedRistretto)?;
        fe25519_mul(&mut dy, &temp, &v).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // x = 2 * s * dx
        let mut two_s = [0u8; 32];
        fe25519_add(&mut two_s, &s, &s).map_err(|_| AppSW::InvalidCompressedRistretto)?;
        fe25519_mul(&mut x, &two_s, &dx).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // Make x positive
        let x_is_neg = fe25519_is_negative(&x);
        fe25519_conditional_negate(&mut x, x_is_neg)
            .map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // y = u1 * dy
        fe25519_mul(&mut y, &u1, &dy).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // t = x * y
        fe25519_mul(&mut t, &x, &y).map_err(|_| AppSW::InvalidCompressedRistretto)?;

        // Check that t is non-negative and y is non-zero
        if fe25519_is_negative(&t) || fe25519_is_zero(&y) {
            return Err(AppSW::InvalidCompressedRistretto);
        }

        Ok(RistrettoPoint { x, y, z: one, t })
    }
}

// Ristretto compression
impl RistrettoPoint {
    pub fn compress(&self) -> Result<CompressedRistretto, AppSW> {
        (|| -> Result<CompressedRistretto, CxError> {
            let mut t0 = [0u8; 32]; // Main workhorse
            let mut t1 = [0u8; 32]; // Secondary temp
            let mut t2 = [0u8; 32]; // Holds values needed later
            let mut t3 = [0u8; 32]; // Holds values needed later
            let mut t4 = [0u8; 32]; // For parallel computations
            let mut t5 = [0u8; 32]; // For parallel computations

            // t0 = Z + Y (u1)
            fe25519_add(&mut t0, &self.z, &self.y)?;

            // t1 = Z - Y (zmy)
            fe25519_sub(&mut t1, &self.z, &self.y)?;

            // t0 = (Z+Y) * (Z-Y) (u1 final)
            fe25519_mul(&mut t2, &t0, &t1)?;
            t0.copy_from_slice(&t2);
            // t0=u1, t1=free, t2=free

            // t1 = X * Y (u2)
            fe25519_mul(&mut t1, &self.x, &self.y)?;

            // t2 = u2^2 (u2_squared)
            fe25519_sq(&mut t2, &t1)?;

            // t3 = u1 * u2^2 (u1_u2u2)
            fe25519_mul(&mut t3, &t0, &t2)?;
            // t0=u1, t1=u2, t2=free, t3=u1_u2u2

            // t2 = inverse sqrt of u1_u2u2 (inv_sqrt)
            let one = FE25519_ONE;
            ristretto255_sqrt_ratio_m1(&mut t2, &one, &t3)?;

            // t0=u1, t1=u2, t2=inv_sqrt, t3=free

            // t3 = inv_sqrt * u1 (den1)
            fe25519_mul(&mut t3, &t2, &t0)?;
            // t0=free, t1=u2, t2=inv_sqrt, t3=den1

            // t0 = inv_sqrt * u2 (den2)  
            fe25519_mul(&mut t0, &t2, &t1)?;
            // t0=den2, t1=free, t2=free, t3=den1

            // t1 = den1 * den2
            fe25519_mul(&mut t1, &t3, &t0)?;
            
            // t2 = den1 * den2 * T (z_inv)
            fe25519_mul(&mut t2, &t1, &self.t)?;
            // t0=den2, t1=free, t2=z_inv, t3=den1

            // t1 = T * z_inv (t_z_inv) - just for the check
            fe25519_mul(&mut t1, &self.t, &t2)?;
            let rotate = fe25519_is_negative(&t1);
            // t0=den2, t1=free, t2=z_inv, t3=den1

            // Now compute the conditional values
            if rotate {
                // t4 = Y * sqrt(-1) (iy)
                fe25519_mul(&mut t4, &self.y, &FE25519_SQRTM1)?;
                
                // t5 = X * sqrt(-1) (ix)
                fe25519_mul(&mut t5, &self.x, &FE25519_SQRTM1)?;
                
                // t1 = den1 * invsqrt(a-d) (eden -> den_inv)
                fe25519_mul(&mut t1, &t3, &ED25519_INVSQRTAMD)?;
                
                // x_ = iy (t4), y_ = ix (t5), den_inv = eden (t1)
            } else {
                // x_ = X, y_ = Y, den_inv = den2
                t4.copy_from_slice(&self.x);
                t5.copy_from_slice(&self.y);
                t1.copy_from_slice(&t0);
            }
            // t0=free, t1=den_inv, t2=z_inv, t3=free, t4=x_, t5=y_

            // t0 = x_ * z_inv (x_z_inv)
            fe25519_mul(&mut t0, &t4, &t2)?;

            // Conditionally negate y_
            if fe25519_is_negative(&t0) {
                fe25519_neg(&mut t3, &t5)?;
                t5.copy_from_slice(&t3);
            }
            // t0=free, t1=den_inv, t2=free, t3=free, t4=free, t5=y_

            // t0 = Z - y_
            fe25519_sub(&mut t0, &self.z, &t5)?;

            // t2 = (Z - y_) * den_inv (s_)
            fe25519_mul(&mut t2, &t0, &t1)?;

            // Make s absolute value
            let mut s = [0u8; 32];
            if fe25519_is_negative(&t2) {
                fe25519_neg(&mut s, &t2)?;
            } else {
                s.copy_from_slice(&t2);
            }

            Ok(CompressedRistretto(s))
        })().map_err(|_| AppSW::KeyDeriveFail)
    }
}

// Inverse square root implementation
pub fn ristretto255_sqrt_ratio_m1(
    x: &mut Fe25519,
    u: &Fe25519,
    v: &Fe25519,
) -> Result<(bool, bool), CxError> {
    // All operations here already work with BE
    let mut v3 = [0u8; 32];
    let mut vxx = [0u8; 32];
    let mut m_root_check = [0u8; 32];
    let mut p_root_check = [0u8; 32];
    let mut f_root_check = [0u8; 32];
    let mut x_sqrtm1 = [0u8; 32];
    let mut temp = [0u8; 32];

    // v3 = v^3
    fe25519_sq(&mut temp, v)?;
    fe25519_mul(&mut v3, &temp, v)?;

    // x = uv^7 = uv^3 * v^4 = uv^3 * (v^2)^2
    fe25519_sq(&mut temp, &v3)?;
    fe25519_mul(x, &temp, u)?;
    fe25519_mul(&mut temp, x, v)?;
    x.copy_from_slice(&temp);

    // x = (uv^7)^((q-5)/8)
    fe25519_pow22523(&mut temp, x)?;
    x.copy_from_slice(&temp);

    // x = uv^3(uv^7)^((q-5)/8)
    fe25519_mul(&mut temp, x, &v3)?;
    fe25519_mul(x, &temp, u)?;

    // vxx = vx^2
    fe25519_sq(&mut temp, x)?;
    fe25519_mul(&mut vxx, &temp, v)?;

    // Check if we have a square root
    fe25519_sub(&mut m_root_check, &vxx, u)?; // vx^2 - u
    fe25519_add(&mut p_root_check, &vxx, u)?; // vx^2 + u
    fe25519_mul(&mut temp, u, &FE25519_SQRTM1)?; // u*sqrt(-1)
    fe25519_add(&mut f_root_check, &vxx, &temp)?; // vx^2 + u*sqrt(-1)

    let has_p_root = fe25519_is_zero(&p_root_check);
    let has_f_root = fe25519_is_zero(&f_root_check);
    let has_m_root = fe25519_is_zero(&m_root_check);

    // x_sqrtm1 = x * sqrt(-1)
    fe25519_mul(&mut x_sqrtm1, x, &FE25519_SQRTM1)?;

    // Select the right square root
    if has_p_root || has_f_root {
        x.copy_from_slice(&x_sqrtm1);
    }

    // Make it positive
    let x_is_neg = fe25519_is_negative(x);
    fe25519_conditional_negate(x, x_is_neg)?;

    Ok((has_m_root || has_p_root || has_f_root, has_m_root))
}

pub fn scalar_mult_ristretto(
    scalar: &[u8; 32],
    point: &RistrettoPoint,
) -> Result<RistrettoPoint, AppSW> {
    let mut result = IDENTITY_POINT;
    let mut temp = *point;
    
    for i in 0..256 {
        let byte_idx = 31 - (i / 8);
        let bit_idx = i % 8;
        if (scalar[byte_idx] >> bit_idx) & 1 != 0 {
            result = edwards_add(&result, &temp)?;
        }
        temp = edwards_add(&temp, &temp)?;
    }
    Ok(result)
}

// Edwards curve point addition
pub fn edwards_add(p: &RistrettoPoint, q: &RistrettoPoint) -> Result<RistrettoPoint, AppSW> {
    (|| -> Result<RistrettoPoint, CxError> {
        let mut t0 = [0u8; 32];
        let mut t1 = [0u8; 32];
        let mut t2 = [0u8; 32];
        let mut t3 = [0u8; 32];
        let mut t4 = [0u8; 32];
        let mut t5 = [0u8; 32];

        // t0 = (Y1-X1)
        fe25519_sub(&mut t0, &p.y, &p.x)?;
        // t1 = (Y2-X2)
        fe25519_sub(&mut t1, &q.y, &q.x)?;
        // t2 = A = (Y1-X1)*(Y2-X2)
        fe25519_mul(&mut t2, &t0, &t1)?;
        
        // t0 = (Y1+X1)
        fe25519_add(&mut t0, &p.y, &p.x)?;
        // t1 = (Y2+X2)
        fe25519_add(&mut t1, &q.y, &q.x)?;
        // t3 = B = (Y1+X1)*(Y2+X2)
        fe25519_mul(&mut t3, &t0, &t1)?;

        // t0 = T1*T2
        fe25519_mul(&mut t0, &p.t, &q.t)?;
        // t1 = 2*d
        fe25519_add(&mut t1, &EDWARDS_D, &EDWARDS_D)?;
        // t4 = C = T1*2*d*T2
        fe25519_mul(&mut t4, &t0, &t1)?;

        // t0 = Z1*Z2
        fe25519_mul(&mut t0, &p.z, &q.z)?;
        // t5 = D = 2*Z1*Z2
        fe25519_add(&mut t5, &t0, &t0)?;

        // t0 = E = B - A
        fe25519_sub(&mut t0, &t3, &t2)?;
        
        // t1 = H = B + A  
        fe25519_add(&mut t1, &t3, &t2)?;
        
        // Now A,B are consumed, can reuse t2,t3
        
        // t2 = F = D - C
        fe25519_sub(&mut t2, &t5, &t4)?;
        
        // t3 = G = D + C
        fe25519_add(&mut t3, &t5, &t4)?;

        // Final computations
        let mut x3 = [0u8; 32];
        let mut y3 = [0u8; 32];
        let mut t3_out = [0u8; 32];
        let mut z3 = [0u8; 32];

        // X3 = E*F
        fe25519_mul(&mut x3, &t0, &t2)?;
        // Y3 = G*H  
        fe25519_mul(&mut y3, &t3, &t1)?;
        // T3 = E*H
        fe25519_mul(&mut t3_out, &t0, &t1)?;
        // Z3 = F*G
        fe25519_mul(&mut z3, &t2, &t3)?;

        Ok(RistrettoPoint {
            x: x3,
            y: y3,
            z: z3,
            t: t3_out,
        })
    })().map_err(|_| AppSW::KeyDeriveFail)
}

pub fn xelis_derive_public_key(private_key: &[u8; 32]) -> Result<CompressedRistretto, AppSW> {
    // private_key should be in BE format
    if is_zero(private_key) {
        return Err(AppSW::KeyDeriveFail);
    }

    // The private key should already be reduced modulo L
    let mut scalar = *private_key;
    scalar_reduce(&mut scalar).map_err(|_| AppSW::KeyDeriveFail)?;

    // Compute s^(-1)
    let s_inv = scalar_invert(&scalar)?;

    // We need to do scalar multiplication: s^(-1) * H
    let result = scalar_mult_ristretto(&s_inv, &XELIS_H_POINT)?;

    // Compress the result
    result.compress()
}

// Xelis-specific public key derivation
pub fn xelis_public_from_private(private_key: &[u8; 32]) -> Result<CompressedRistretto, AppSW> {
    // private_key should be in BE format
    if is_zero(private_key) {
        return Err(AppSW::KeyDeriveFail);
    }

    // Compute s^(-1)
    let s_inv = scalar_invert(private_key)?;

    // Compute s^(-1) * H
    let public_point = scalar_mult_ristretto(&s_inv, &XELIS_H_POINT)?;

    // Compress the result
    public_point.compress()
}

pub fn is_valid_compressed_ristretto(bytes: &[u8; 32], is_le: bool) -> bool {
    // For p = 2^255 - 19, we only need to check:
    // 1. High bit is clear (ensures < 2^255)
    // 2. If all other bits are set, low byte must be < 0xed

    let (msb_idx, lsb_idx) = if is_le { (31, 0) } else { (0, 31) };

    // High bit must be clear
    if bytes[msb_idx] & 0x80 != 0 {
        return false;
    }

    // Quick accept: if MSB < 0x7f, definitely valid
    if bytes[msb_idx] < 0x7f {
        return true;
    }

    // MSB is 0x7f - only invalid if all other bits set and LSB >= 0xed
    // This is because p = 0x7fff...ffed

    // Check if potential overflow (all middle bytes are 0xff)
    let range = if is_le { 1..31 } else { 1..31 };
    let all_ff = bytes[range].iter().all(|&b| b == 0xff);

    // Valid if not all 0xff, or if all 0xff then LSB < 0xed
    !all_ff || bytes[lsb_idx] < 0xed
}

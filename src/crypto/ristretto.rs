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

pub fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

// Helper functions - all work with BE internally
pub fn fe25519_mul(h: &mut Fe25519, f: &Fe25519, g: &Fe25519) -> Result<(), CxError> {
    unsafe {
        let result = cx_math_multm_no_throw(
            h.as_mut_ptr(),
            f.as_ptr(),
            g.as_ptr(),
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

pub fn fe25519_add(h: &mut Fe25519, f: &Fe25519, g: &Fe25519) -> Result<(), CxError> {
    unsafe {
        let result = cx_math_addm_no_throw(
            h.as_mut_ptr(),
            f.as_ptr(),
            g.as_ptr(),
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

pub fn fe25519_sub(h: &mut Fe25519, f: &Fe25519, g: &Fe25519) -> Result<(), CxError> {
    unsafe {
        let result = cx_math_subm_no_throw(
            h.as_mut_ptr(),
            f.as_ptr(),
            g.as_ptr(),
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

pub fn fe25519_sq(h: &mut Fe25519, f: &Fe25519) -> Result<(), CxError> {
    fe25519_mul(h, f, f)
}

fn fe25519_is_zero(f: &Fe25519) -> bool {
    is_zero(f)
}

pub fn fe25519_is_negative(f: &Fe25519) -> bool {
    // In BE, the least significant bit is at index 31
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
    if negate {
        let mut neg = [0u8; 32];
        fe25519_neg(&mut neg, f)?;
        f.copy_from_slice(&neg);
    }
    Ok(())
}

pub fn fe25519_one() -> Fe25519 {
    let mut one = [0u8; 32];
    one[31] = 1; // In BE, the least significant byte is at index 31
    one
}

// Ristretto decompression
impl CompressedRistretto {
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
        let one = fe25519_one();
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
        let mut u1 = [0u8; 32];
        let mut u2 = [0u8; 32];
        let mut u1_u2u2 = [0u8; 32];
        let mut inv_sqrt = [0u8; 32];
        let mut den1 = [0u8; 32];
        let mut den2 = [0u8; 32];
        let mut z_inv = [0u8; 32];
        let mut ix = [0u8; 32];
        let mut iy = [0u8; 32];
        let mut eden = [0u8; 32];
        let mut t_z_inv = [0u8; 32];
        let mut x_ = [0u8; 32];
        let mut y_ = [0u8; 32];
        let mut den_inv = [0u8; 32];
        let mut x_z_inv = [0u8; 32];
        let mut s_ = [0u8; 32];
        let mut s = [0u8; 32];
        let mut zmy = [0u8; 32];
        let mut temp = [0u8; 32];

        // u1 = Z + Y
        fe25519_add(&mut u1, &self.z, &self.y).map_err(|_| AppSW::TxSignFail)?;

        // zmy = Z - Y
        fe25519_sub(&mut zmy, &self.z, &self.y).map_err(|_| AppSW::TxSignFail)?;

        // u1 = (Z+Y) * (Z-Y)
        fe25519_mul(&mut temp, &u1, &zmy).map_err(|_| AppSW::TxSignFail)?;
        u1.copy_from_slice(&temp);

        // u2 = X * Y
        fe25519_mul(&mut u2, &self.x, &self.y).map_err(|_| AppSW::TxSignFail)?;

        // u1_u2u2 = u1 * u2^2
        let mut u2_squared = [0u8; 32];
        fe25519_sq(&mut u2_squared, &u2).map_err(|_| AppSW::TxSignFail)?;
        fe25519_mul(&mut u1_u2u2, &u1, &u2_squared).map_err(|_| AppSW::TxSignFail)?;

        // Compute inverse square root of u1_u2u2
        let one = fe25519_one();
        let (ok, _) = ristretto255_sqrt_ratio_m1(&mut inv_sqrt, &one, &u1_u2u2)
            .map_err(|_| AppSW::TxSignFail)?;

        if !ok {
            return Err(AppSW::TxSignFail);
        }

        // den1 = inv_sqrt * u1
        fe25519_mul(&mut den1, &inv_sqrt, &u1).map_err(|_| AppSW::TxSignFail)?;

        // den2 = inv_sqrt * u2
        fe25519_mul(&mut den2, &inv_sqrt, &u2).map_err(|_| AppSW::TxSignFail)?;

        // z_inv = den1 * den2 * T
        fe25519_mul(&mut temp, &den1, &den2).map_err(|_| AppSW::TxSignFail)?;
        fe25519_mul(&mut z_inv, &temp, &self.t).map_err(|_| AppSW::TxSignFail)?;

        // ix = X * sqrt(-1)
        fe25519_mul(&mut ix, &self.x, &FE25519_SQRTM1).map_err(|_| AppSW::TxSignFail)?;

        // iy = Y * sqrt(-1)
        fe25519_mul(&mut iy, &self.y, &FE25519_SQRTM1).map_err(|_| AppSW::TxSignFail)?;

        // eden = den1 * invsqrt(a-d)
        fe25519_mul(&mut eden, &den1, &ED25519_INVSQRTAMD).map_err(|_| AppSW::TxSignFail)?;

        // t_z_inv = T * z_inv
        fe25519_mul(&mut t_z_inv, &self.t, &z_inv).map_err(|_| AppSW::TxSignFail)?;

        // Rotate if t_z_inv is negative
        let rotate = fe25519_is_negative(&t_z_inv);

        // Copy initial values
        x_.copy_from_slice(&self.x);
        y_.copy_from_slice(&self.y);
        den_inv.copy_from_slice(&den2);

        // Conditional rotate
        if rotate {
            x_.copy_from_slice(&iy);
            y_.copy_from_slice(&ix);
            den_inv.copy_from_slice(&eden);
        }

        // x_z_inv = x_ * z_inv
        fe25519_mul(&mut x_z_inv, &x_, &z_inv).map_err(|_| AppSW::TxSignFail)?;

        // Conditionally negate y_
        if fe25519_is_negative(&x_z_inv) {
            fe25519_neg(&mut temp, &y_).map_err(|_| AppSW::TxSignFail)?;
            y_.copy_from_slice(&temp);
        }

        // s_ = (Z - y_) * den_inv
        fe25519_sub(&mut temp, &self.z, &y_).map_err(|_| AppSW::TxSignFail)?;
        fe25519_mul(&mut s_, &temp, &den_inv).map_err(|_| AppSW::TxSignFail)?;

        // Make s absolute value
        if fe25519_is_negative(&s_) {
            fe25519_neg(&mut s, &s_).map_err(|_| AppSW::TxSignFail)?;
        } else {
            s.copy_from_slice(&s_);
        }

        // Return as BE internally
        Ok(CompressedRistretto(s))
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
    // scalar is already in BE format
    let mut result = RistrettoPoint {
        x: [0; 32],
        y: fe25519_one(),
        z: fe25519_one(),
        t: [0; 32],
    }; // Identity

    let mut temp = *point;

    // Process scalar from LSB to MSB
    // In BE format, we need to process from the last byte
    for i in 0..256 {
        let byte_index = 31 - (i / 8); // Start from last byte in BE
        let bit_index = i % 8;
        let bit = (scalar[byte_index] >> bit_index) & 1;

        if bit == 1 {
            result = edwards_add(&result, &temp)?;
        }

        temp = edwards_double(&temp)?;
    }

    Ok(result)
}

// Edwards curve point addition
pub fn edwards_add(p: &RistrettoPoint, q: &RistrettoPoint) -> Result<RistrettoPoint, AppSW> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    let mut d = [0u8; 32];
    let mut e = [0u8; 32];
    let mut f = [0u8; 32];
    let mut g = [0u8; 32];
    let mut h = [0u8; 32];
    let mut temp1 = [0u8; 32];
    let mut temp2 = [0u8; 32];

    // A = (Y1-X1)*(Y2-X2)
    fe25519_sub(&mut temp1, &p.y, &p.x).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_sub(&mut temp2, &q.y, &q.x).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_mul(&mut a, &temp1, &temp2).map_err(|_| AppSW::KeyDeriveFail)?;

    // B = (Y1+X1)*(Y2+X2)
    fe25519_add(&mut temp1, &p.y, &p.x).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_add(&mut temp2, &q.y, &q.x).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_mul(&mut b, &temp1, &temp2).map_err(|_| AppSW::KeyDeriveFail)?;

    // C = T1*2*d*T2
    fe25519_mul(&mut temp1, &p.t, &q.t).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_add(&mut temp2, &EDWARDS_D, &EDWARDS_D).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_mul(&mut c, &temp1, &temp2).map_err(|_| AppSW::KeyDeriveFail)?;

    // D = Z1*2*Z2
    fe25519_mul(&mut temp1, &p.z, &q.z).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_add(&mut d, &temp1, &temp1).map_err(|_| AppSW::KeyDeriveFail)?;

    // E = B-A
    fe25519_sub(&mut e, &b, &a).map_err(|_| AppSW::KeyDeriveFail)?;

    // F = D-C
    fe25519_sub(&mut f, &d, &c).map_err(|_| AppSW::KeyDeriveFail)?;

    // G = D+C
    fe25519_add(&mut g, &d, &c).map_err(|_| AppSW::KeyDeriveFail)?;

    // H = B+A
    fe25519_add(&mut h, &b, &a).map_err(|_| AppSW::KeyDeriveFail)?;

    // X3 = E*F
    let mut x3 = [0u8; 32];
    fe25519_mul(&mut x3, &e, &f).map_err(|_| AppSW::KeyDeriveFail)?;

    // Y3 = G*H
    let mut y3 = [0u8; 32];
    fe25519_mul(&mut y3, &g, &h).map_err(|_| AppSW::KeyDeriveFail)?;

    // T3 = E*H
    let mut t3 = [0u8; 32];
    fe25519_mul(&mut t3, &e, &h).map_err(|_| AppSW::KeyDeriveFail)?;

    // Z3 = F*G
    let mut z3 = [0u8; 32];
    fe25519_mul(&mut z3, &f, &g).map_err(|_| AppSW::KeyDeriveFail)?;

    Ok(RistrettoPoint {
        x: x3,
        y: y3,
        z: z3,
        t: t3,
    })
}

// Edwards curve point doubling
pub fn edwards_double(p: &RistrettoPoint) -> Result<RistrettoPoint, AppSW> {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    let mut c = [0u8; 32];
    let mut e = [0u8; 32];
    let mut g = [0u8; 32];
    let mut f = [0u8; 32];
    let mut h = [0u8; 32];
    let mut temp1 = [0u8; 32];
    let mut temp2 = [0u8; 32];

    // A = X1^2
    fe25519_sq(&mut a, &p.x).map_err(|_| AppSW::KeyDeriveFail)?;

    // B = Y1^2
    fe25519_sq(&mut b, &p.y).map_err(|_| AppSW::KeyDeriveFail)?;

    // C = 2*Z1^2
    fe25519_sq(&mut temp1, &p.z).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_add(&mut c, &temp1, &temp1).map_err(|_| AppSW::KeyDeriveFail)?;

    // H = A+B
    fe25519_add(&mut h, &a, &b).map_err(|_| AppSW::KeyDeriveFail)?;

    // E = H-(X1+Y1)^2
    fe25519_add(&mut temp1, &p.x, &p.y).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_sq(&mut temp2, &temp1).map_err(|_| AppSW::KeyDeriveFail)?;
    fe25519_sub(&mut e, &h, &temp2).map_err(|_| AppSW::KeyDeriveFail)?;

    // G = A-B
    fe25519_sub(&mut g, &a, &b).map_err(|_| AppSW::KeyDeriveFail)?;

    // F = C+G
    fe25519_add(&mut f, &c, &g).map_err(|_| AppSW::KeyDeriveFail)?;

    // X3 = E*F
    let mut x3 = [0u8; 32];
    fe25519_mul(&mut x3, &e, &f).map_err(|_| AppSW::KeyDeriveFail)?;

    // Y3 = G*H
    let mut y3 = [0u8; 32];
    fe25519_mul(&mut y3, &g, &h).map_err(|_| AppSW::KeyDeriveFail)?;

    // T3 = E*H
    let mut t3 = [0u8; 32];
    fe25519_mul(&mut t3, &e, &h).map_err(|_| AppSW::KeyDeriveFail)?;

    // Z3 = F*G
    let mut z3 = [0u8; 32];
    fe25519_mul(&mut z3, &f, &g).map_err(|_| AppSW::KeyDeriveFail)?;

    Ok(RistrettoPoint {
        x: x3,
        y: y3,
        z: z3,
        t: t3,
    })
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

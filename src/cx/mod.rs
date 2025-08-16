extern "C" {
    pub fn cx_math_addm_no_throw(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;
    pub fn cx_math_subm_no_throw(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;
    pub fn cx_math_multm_no_throw(r: *mut u8, a: *const u8, b: *const u8, m: *const u8, len: usize) -> u32;
    pub fn cx_math_powm_no_throw(r: *mut u8, a: *const u8, e: *const u8, e_len: usize, m: *const u8, len: usize) -> u32;
    pub fn cx_ecfp_scalar_mult_no_throw(curve: u8, p: *mut u8, k: *const u8, k_len: usize) -> u32;
    pub fn cx_math_modm_no_throw(r: *mut u8, a_len: usize, m: *const u8, m_len: usize) -> u32;
    pub fn cx_rng_no_throw(r: *mut u8, len: usize) -> u32;
}

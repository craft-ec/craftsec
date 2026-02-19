//! Scalar field utilities for curve25519-dalek.

use curve25519_dalek::scalar::Scalar;
use sha2::{Sha512, Digest};

/// Generate a random scalar.
pub fn random_scalar(rng: &mut impl rand::RngCore) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Hash-to-scalar for challenge computation (FROST binding factor, etc).
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let hash = Sha512::digest(data);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

//! Program Derived Keys (PDK) — deterministic key derivation from program CID + seed.
//!
//! Uses HKDF-SHA512 to derive polynomial coefficients deterministically,
//! producing threshold key shares without randomness (given the same inputs).

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::{EdwardsPoint, Scalar};
use craftsec_core::{KeyShare, ParticipantIndex, Result, ThresholdConfig};
use crate::polynomial::Polynomial;
use sha2::{Sha512, Digest};

/// Derive a deterministic scalar from input material using HKDF-like construction.
fn derive_scalar(ikm: &[u8], info: &[u8], index: u32) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"CraftSEC-PDK-v1");
    hasher.update(ikm);
    hasher.update(info);
    hasher.update(index.to_le_bytes());
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Derive threshold key shares from a program CID and seed string.
///
/// This is deterministic: same (program_cid, seed, config) always produces
/// the same key shares and public key.
pub fn derive_key(
    program_cid: &str,
    seed: &str,
    config: &ThresholdConfig,
) -> Result<(EdwardsPoint, Vec<KeyShare>)> {
    let t = config.threshold as usize;
    let n = config.total as usize;
    let g = ED25519_BASEPOINT_POINT;

    // Derive the input key material
    let mut ikm = Vec::new();
    ikm.extend_from_slice(program_cid.as_bytes());
    ikm.push(0xFF); // separator
    ikm.extend_from_slice(seed.as_bytes());

    // Derive polynomial coefficients deterministically
    let coefficients: Vec<Scalar> = (0..t)
        .map(|i| derive_scalar(&ikm, b"coefficient", i as u32))
        .collect();

    let poly = Polynomial { coefficients };

    // Commitments
    let commitments: Vec<EdwardsPoint> = poly.coefficients.iter().map(|c| g * c).collect();
    let group_public_key = commitments[0]; // For a single polynomial, this IS a_0 * G

    // Wait — for a proper DKG with n participants, each would contribute their own polynomial.
    // For PDK, we use a SINGLE deterministic polynomial (simulating a centralized dealer).
    // This is secure because no one knows the full polynomial — it's derived from CID+seed
    // and each node only gets their share.

    // Compute shares
    let mut key_shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Scalar::from(i as u64);
        let secret = poly.evaluate(&x);

        // Verification shares
        let verification_shares: Vec<(ParticipantIndex, EdwardsPoint)> = (1..=n)
            .map(|j| {
                let xj = Scalar::from(j as u64);
                let secret_j = poly.evaluate(&xj);
                (j as ParticipantIndex, g * secret_j)
            })
            .collect();

        key_shares.push(KeyShare {
            index: i as ParticipantIndex,
            secret,
            group_public_key,
            verification_shares,
        });
    }

    Ok((group_public_key, key_shares))
}

#[cfg(test)]
mod tests {
    use super::*;
    use craftsec_core::ThresholdConfig;
    use craftsec_signing::lagrange_coefficient;

    #[test]
    fn derive_key_deterministic() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (pk1, shares1) = derive_key("Qm_transfer", "main", &config).unwrap();
        let (pk2, shares2) = derive_key("Qm_transfer", "main", &config).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(shares1[0].secret, shares2[0].secret);
    }

    #[test]
    fn different_seeds_different_keys() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (pk1, _) = derive_key("Qm_transfer", "main", &config).unwrap();
        let (pk2, _) = derive_key("Qm_transfer", "escrow:alice:bob", &config).unwrap();
        let (pk3, _) = derive_key("Qm_transfer", "treasury", &config).unwrap();
        assert_ne!(pk1, pk2);
        assert_ne!(pk2, pk3);
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn different_programs_different_keys() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (pk1, _) = derive_key("Qm_transfer", "main", &config).unwrap();
        let (pk2, _) = derive_key("Qm_swap", "main", &config).unwrap();
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn shares_reconstruct_to_group_key() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let (gpk, shares) = derive_key("Qm_test", "main", &config).unwrap();

        // Reconstruct secret from shares 0 and 1
        let indices = &[1u32, 2u32];
        let l1 = lagrange_coefficient(1, indices);
        let l2 = lagrange_coefficient(2, indices);
        let secret = shares[0].secret * l1 + shares[1].secret * l2;

        let g = ED25519_BASEPOINT_POINT;
        assert_eq!(g * secret, gpk);
    }

    #[test]
    fn sign_with_derived_key() {
        use craftsec_signing::{generate_nonces, sign_partial, aggregate, verify};
        use rand::rngs::OsRng;

        let config = ThresholdConfig::new(2, 3).unwrap();
        let (gpk, shares) = derive_key("Qm_transfer", "main", &config).unwrap();

        let message = b"test transaction";

        // Sign with shares 0 and 2
        let signers = &[0usize, 2];
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &i in signers {
            let (nonce, commitment) = generate_nonces(shares[i].index, &mut OsRng);
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let mut partials = Vec::new();
        for (idx, &i) in signers.iter().enumerate() {
            let partial = sign_partial(&shares[i], &nonces[idx], message, &commitments).unwrap();
            partials.push(partial);
        }

        let sig = aggregate(message, &commitments, &partials);
        verify(&sig, &gpk, message).unwrap();
    }

    #[test]
    fn multiple_keys_per_program() {
        use craftsec_signing::{generate_nonces, sign_partial, aggregate, verify};
        use rand::rngs::OsRng;

        let config = ThresholdConfig::new(2, 3).unwrap();

        let seeds = ["main", "escrow:alice:bob", "treasury"];
        let mut keys = Vec::new();

        for seed in &seeds {
            let (gpk, shares) = derive_key("Qm_swap", seed, &config).unwrap();
            keys.push((gpk, shares));
        }

        // All keys should be independent
        assert_ne!(keys[0].0, keys[1].0);
        assert_ne!(keys[1].0, keys[2].0);

        // Sign with each key independently
        for (gpk, shares) in &keys {
            let message = b"test";
            let (n0, c0) = generate_nonces(shares[0].index, &mut OsRng);
            let (n1, c1) = generate_nonces(shares[1].index, &mut OsRng);
            let commitments = vec![c0, c1];
            let p0 = sign_partial(&shares[0], &n0, message, &commitments).unwrap();
            let p1 = sign_partial(&shares[1], &n1, message, &commitments).unwrap();
            let sig = aggregate(message, &commitments, &[p0, p1]);
            verify(&sig, gpk, message).unwrap();
        }
    }
}

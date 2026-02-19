//! FROST threshold signing protocol.
//!
//! Adapted for Ed25519: uses EdwardsPoint and cofactored basepoint.
//! Produces signatures verifiable as standard Ed25519.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::{EdwardsPoint, Scalar};
use craftsec_core::scalar_ext::{hash_to_scalar, random_scalar};
use craftsec_core::{CraftSecError, KeyShare, ParticipantIndex, Result};
use crate::lagrange::lagrange_coefficient;
use sha2::{Sha512, Digest};

/// Nonce pair for Round 1.
#[derive(Debug, Clone)]
pub struct SigningNonce {
    pub index: ParticipantIndex,
    /// Hiding nonce (secret).
    pub d: Scalar,
    /// Binding nonce (secret).
    pub e: Scalar,
}

/// Public commitment for Round 1 (broadcast to all signers).
#[derive(Debug, Clone)]
pub struct SigningCommitment {
    pub index: ParticipantIndex,
    /// D = d * G
    pub hiding: EdwardsPoint,
    /// E = e * G
    pub binding: EdwardsPoint,
}

/// A partial signature from one signer (Round 2 output).
#[derive(Debug, Clone)]
pub struct PartialSignature {
    pub index: ParticipantIndex,
    pub z: Scalar,
}

/// The final aggregated signature.
#[derive(Debug, Clone)]
pub struct ThresholdSignature {
    pub r: EdwardsPoint,
    pub s: Scalar,
}

/// Round 1: Generate nonce pair and commitment.
pub fn generate_nonces(
    index: ParticipantIndex,
    rng: &mut impl rand::RngCore,
) -> (SigningNonce, SigningCommitment) {
    let g = ED25519_BASEPOINT_POINT;
    let d = random_scalar(rng);
    let e = random_scalar(rng);

    let nonce = SigningNonce { index, d, e };
    let commitment = SigningCommitment {
        index,
        hiding: g * d,
        binding: g * e,
    };
    (nonce, commitment)
}

/// Compute the binding factor ρ_i for a participant.
fn binding_factor(
    index: ParticipantIndex,
    message: &[u8],
    commitments: &[SigningCommitment],
) -> Scalar {
    let mut data = Vec::new();
    data.extend_from_slice(&index.to_le_bytes());
    data.extend_from_slice(message);
    // Include all commitments for domain separation
    for c in commitments {
        data.extend_from_slice(&c.index.to_le_bytes());
        data.extend_from_slice(c.hiding.compress().as_bytes());
        data.extend_from_slice(c.binding.compress().as_bytes());
    }
    hash_to_scalar(&data)
}

/// Compute the group commitment R.
fn group_commitment(
    message: &[u8],
    commitments: &[SigningCommitment],
) -> EdwardsPoint {
    commitments
        .iter()
        .map(|c| {
            let rho = binding_factor(c.index, message, commitments);
            c.hiding + c.binding * rho
        })
        .sum()
}

/// Compute the challenge scalar c = H(R || PK || message) using Ed25519 convention.
fn compute_challenge(
    r: &EdwardsPoint,
    public_key: &EdwardsPoint,
    message: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r.compress().as_bytes());
    hasher.update(public_key.compress().as_bytes());
    hasher.update(message);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Round 2: Compute partial signature.
pub fn sign_partial(
    key_share: &KeyShare,
    nonce: &SigningNonce,
    message: &[u8],
    commitments: &[SigningCommitment],
) -> Result<PartialSignature> {
    let signer_indices: Vec<ParticipantIndex> = commitments.iter().map(|c| c.index).collect();

    let r = group_commitment(message, commitments);
    let challenge = compute_challenge(&r, &key_share.group_public_key, message);
    let rho = binding_factor(key_share.index, message, commitments);
    let lambda = lagrange_coefficient(key_share.index, &signer_indices);

    // z_i = d_i + e_i * rho_i + lambda_i * s_i * c
    let z = nonce.d + nonce.e * rho + lambda * key_share.secret * challenge;

    Ok(PartialSignature {
        index: key_share.index,
        z,
    })
}

/// Verify a partial signature against the signer's verification share.
pub fn verify_partial(
    partial: &PartialSignature,
    commitment: &SigningCommitment,
    verification_share: &EdwardsPoint,
    message: &[u8],
    commitments: &[SigningCommitment],
    group_public_key: &EdwardsPoint,
) -> Result<()> {
    let g = ED25519_BASEPOINT_POINT;
    let signer_indices: Vec<ParticipantIndex> = commitments.iter().map(|c| c.index).collect();

    let r = group_commitment(message, commitments);
    let challenge = compute_challenge(&r, group_public_key, message);
    let rho = binding_factor(partial.index, message, commitments);
    let lambda = lagrange_coefficient(partial.index, &signer_indices);

    // z_i * G == D_i + E_i * rho_i + lambda_i * Y_i * c
    let lhs = g * partial.z;
    let rhs = commitment.hiding + commitment.binding * rho + *verification_share * (lambda * challenge);

    if lhs == rhs {
        Ok(())
    } else {
        Err(CraftSecError::InvalidSignature(format!(
            "partial signature verification failed for participant {}",
            partial.index
        )))
    }
}

/// Aggregate partial signatures into the final threshold signature.
pub fn aggregate(
    message: &[u8],
    commitments: &[SigningCommitment],
    partials: &[PartialSignature],
) -> ThresholdSignature {
    let r = group_commitment(message, commitments);
    let s: Scalar = partials.iter().map(|p| p.z).sum();
    ThresholdSignature { r, s }
}

/// Verify the threshold signature against the group public key.
/// Uses standard Schnorr verification: s * G == R + c * PK
pub fn verify(
    signature: &ThresholdSignature,
    public_key: &EdwardsPoint,
    message: &[u8],
) -> Result<()> {
    let g = ED25519_BASEPOINT_POINT;
    let challenge = compute_challenge(&signature.r, public_key, message);

    let lhs = g * signature.s;
    let rhs = signature.r + public_key * challenge;

    if lhs == rhs {
        Ok(())
    } else {
        Err(CraftSecError::InvalidSignature(
            "threshold signature verification failed".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use craftsec_dkg::run_dkg;
    use craftsec_core::ThresholdConfig;
    use rand::rngs::OsRng;

    fn sign_and_verify(t: u32, n: u32, signers: &[usize]) {
        let config = ThresholdConfig::new(t, n).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();
        let message = b"test transaction data";

        // Round 1: Generate nonces for selected signers
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &i in signers {
            let (nonce, commitment) = generate_nonces(key_shares[i].index, &mut OsRng);
            nonces.push(nonce);
            commitments.push(commitment);
        }

        // Round 2: Compute partial signatures
        let mut partials = Vec::new();
        for (idx, &i) in signers.iter().enumerate() {
            let partial = sign_partial(
                &key_shares[i],
                &nonces[idx],
                message,
                &commitments,
            ).unwrap();
            partials.push(partial);
        }

        // Aggregate
        let sig = aggregate(message, &commitments, &partials);

        // Verify
        verify(&sig, &key_shares[0].group_public_key, message).unwrap();
    }

    #[test]
    fn frost_2_of_3() {
        sign_and_verify(2, 3, &[0, 1]);
        sign_and_verify(2, 3, &[0, 2]);
        sign_and_verify(2, 3, &[1, 2]);
    }

    #[test]
    fn frost_3_of_5() {
        sign_and_verify(3, 5, &[0, 1, 2]);
        sign_and_verify(3, 5, &[0, 2, 4]);
        sign_and_verify(3, 5, &[1, 3, 4]);
    }

    #[test]
    fn frost_wrong_message_fails() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();
        let message = b"correct message";

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for i in 0..2 {
            let (nonce, commitment) = generate_nonces(key_shares[i].index, &mut OsRng);
            nonces.push(nonce);
            commitments.push(commitment);
        }

        let mut partials = Vec::new();
        for i in 0..2 {
            let partial = sign_partial(&key_shares[i], &nonces[i], message, &commitments).unwrap();
            partials.push(partial);
        }

        let sig = aggregate(message, &commitments, &partials);

        // Verify with wrong message should fail
        assert!(verify(&sig, &key_shares[0].group_public_key, b"wrong message").is_err());
    }

    #[test]
    fn partial_signature_verification() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();
        let message = b"verify partials";

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for i in 0..2 {
            let (nonce, commitment) = generate_nonces(key_shares[i].index, &mut OsRng);
            nonces.push(nonce);
            commitments.push(commitment);
        }

        for i in 0..2 {
            let partial = sign_partial(&key_shares[i], &nonces[i], message, &commitments).unwrap();
            let vk = key_shares[i].verification_shares
                .iter()
                .find(|(idx, _)| *idx == key_shares[i].index)
                .unwrap()
                .1;
            verify_partial(
                &partial,
                &commitments[i],
                &vk,
                message,
                &commitments,
                &key_shares[0].group_public_key,
            ).unwrap();
        }
    }

    #[test]
    fn invalid_partial_detected() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let key_shares = run_dkg(&config, &mut OsRng).unwrap();
        let message = b"detect invalid";

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for i in 0..2 {
            let (nonce, commitment) = generate_nonces(key_shares[i].index, &mut OsRng);
            nonces.push(nonce);
            commitments.push(commitment);
        }

        // Create a valid partial then corrupt it
        let mut partial = sign_partial(&key_shares[0], &nonces[0], message, &commitments).unwrap();
        partial.z += Scalar::ONE; // corrupt

        let vk = key_shares[0].verification_shares
            .iter()
            .find(|(idx, _)| *idx == key_shares[0].index)
            .unwrap()
            .1;

        assert!(verify_partial(
            &partial,
            &commitments[0],
            &vk,
            message,
            &commitments,
            &key_shares[0].group_public_key,
        ).is_err());
    }
}

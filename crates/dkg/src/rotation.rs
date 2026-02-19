//! Proactive Secret Sharing — key rotation without changing the group public key.
//!
//! Each participant generates a random zero-polynomial (constant term = 0),
//! distributes shares to all participants, and everyone adds the received
//! zero-shares to their existing share. The group public key is preserved
//! because sum of zero-constant-terms = 0.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::{EdwardsPoint, Scalar};
use craftsec_core::{KeyShare, ParticipantIndex, Result, ThresholdConfig};
use crate::polynomial::Polynomial;
use crate::feldman::verify_share;

/// A participant's zero-share contribution for rotation.
#[derive(Debug, Clone)]
pub struct RotationContribution {
    pub index: ParticipantIndex,
    /// Commitments to the zero-polynomial coefficients (C_0 should be identity).
    pub commitments: Vec<EdwardsPoint>,
    /// Zero-shares for each participant.
    pub shares: Vec<(ParticipantIndex, Scalar)>,
}

/// Rotate key shares using proactive secret sharing.
///
/// Each participant contributes a random polynomial with constant term 0.
/// The sum of all zero-shares is added to each participant's existing share.
/// The group public key remains unchanged.
///
/// `old_shares` — current key shares for all participants.
/// `new_config` — the threshold config (can differ in threshold but must have same n).
///
/// Returns new key shares with the same group public key.
pub fn rotate_shares(
    old_shares: &[KeyShare],
    new_config: &ThresholdConfig,
    rng: &mut impl rand::RngCore,
) -> Result<Vec<KeyShare>> {
    let n = old_shares.len();
    let t = new_config.threshold as usize;
    let g = ED25519_BASEPOINT_POINT;
    let group_public_key = old_shares[0].group_public_key;

    // Each participant generates a zero-polynomial: f_i(0) = 0
    let mut contributions = Vec::with_capacity(n);
    for i in 1..=n {
        let poly = Polynomial::random(t - 1, Scalar::ZERO, rng);

        // Commitments (C_0 should be identity point since a_0 = 0)
        let commitments: Vec<EdwardsPoint> = poly
            .coefficients
            .iter()
            .map(|c| g * c)
            .collect();

        // Verify C_0 is identity
        debug_assert_eq!(commitments[0], EdwardsPoint::default());

        let shares: Vec<(ParticipantIndex, Scalar)> = (1..=n)
            .map(|j| {
                let x = Scalar::from(j as u64);
                (j as ParticipantIndex, poly.evaluate(&x))
            })
            .collect();

        contributions.push(RotationContribution {
            index: i as ParticipantIndex,
            commitments,
            shares,
        });
    }

    // Verify all zero-shares
    for receiver_idx in 1..=n {
        for contribution in &contributions {
            let share_value = contribution.shares[receiver_idx - 1].1;
            verify_share(
                receiver_idx as ParticipantIndex,
                &share_value,
                &contribution.commitments,
            )?;
        }
    }

    // Each participant adds all received zero-shares to their existing share
    let mut new_shares = Vec::with_capacity(n);
    for i in 1..=n {
        let old_secret = old_shares[i - 1].secret;

        // Sum of zero-shares for participant i
        let delta: Scalar = contributions
            .iter()
            .map(|c| c.shares[i - 1].1)
            .sum();

        let new_secret = old_secret + delta;

        // Recompute verification shares
        let verification_shares: Vec<(ParticipantIndex, EdwardsPoint)> = (1..=n)
            .map(|j| {
                let old_vk = old_shares[j - 1]
                    .verification_shares
                    .iter()
                    .find(|(idx, _)| *idx == j as ParticipantIndex)
                    .unwrap()
                    .1;
                let delta_j: Scalar = contributions
                    .iter()
                    .map(|c| c.shares[j - 1].1)
                    .sum();
                (j as ParticipantIndex, old_vk + g * delta_j)
            })
            .collect();

        new_shares.push(KeyShare {
            index: i as ParticipantIndex,
            secret: new_secret,
            group_public_key,
            verification_shares,
        });
    }

    Ok(new_shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feldman::run_dkg;
    use craftsec_core::ThresholdConfig;
    use craftsec_signing::{generate_nonces, sign_partial, aggregate, verify};
    use rand::rngs::OsRng;

    #[test]
    fn rotate_2_of_3_preserves_public_key() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let old_shares = run_dkg(&config, &mut OsRng).unwrap();
        let old_gpk = old_shares[0].group_public_key;

        let new_shares = rotate_shares(&old_shares, &config, &mut OsRng).unwrap();

        // Public key unchanged
        assert_eq!(new_shares[0].group_public_key, old_gpk);
        for s in &new_shares {
            assert_eq!(s.group_public_key, old_gpk);
        }
    }

    #[test]
    fn new_shares_can_sign() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let old_shares = run_dkg(&config, &mut OsRng).unwrap();
        let new_shares = rotate_shares(&old_shares, &config, &mut OsRng).unwrap();

        let message = b"post-rotation message";
        let signers = &[0usize, 2];

        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        for &i in signers {
            let (n, c) = generate_nonces(new_shares[i].index, &mut OsRng);
            nonces.push(n);
            commitments.push(c);
        }

        let mut partials = Vec::new();
        for (idx, &i) in signers.iter().enumerate() {
            let p = sign_partial(&new_shares[i], &nonces[idx], message, &commitments).unwrap();
            partials.push(p);
        }

        let sig = aggregate(message, &commitments, &partials);
        verify(&sig, &new_shares[0].group_public_key, message).unwrap();
    }

    #[test]
    fn old_shares_cannot_sign_valid_after_rotation() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let old_shares = run_dkg(&config, &mut OsRng).unwrap();
        let new_shares = rotate_shares(&old_shares, &config, &mut OsRng).unwrap();

        // Secrets should have changed
        assert_ne!(old_shares[0].secret, new_shares[0].secret);
        assert_ne!(old_shares[1].secret, new_shares[1].secret);
        assert_ne!(old_shares[2].secret, new_shares[2].secret);

        // Mixing old and new shares should produce invalid signatures
        // Use old_share[0] + new_share[1] — these are incompatible
        let message = b"mixed shares test";
        let (n0, c0) = generate_nonces(old_shares[0].index, &mut OsRng);
        let (n1, c1) = generate_nonces(new_shares[1].index, &mut OsRng);
        let commitments = vec![c0, c1];

        let p0 = sign_partial(&old_shares[0], &n0, message, &commitments).unwrap();
        let p1 = sign_partial(&new_shares[1], &n1, message, &commitments).unwrap();

        let sig = aggregate(message, &commitments, &[p0, p1]);
        // This should fail verification
        assert!(verify(&sig, &new_shares[0].group_public_key, message).is_err());
    }

    #[test]
    fn double_rotation() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares0 = run_dkg(&config, &mut OsRng).unwrap();
        let gpk = shares0[0].group_public_key;

        let shares1 = rotate_shares(&shares0, &config, &mut OsRng).unwrap();
        let shares2 = rotate_shares(&shares1, &config, &mut OsRng).unwrap();

        // Public key still the same
        assert_eq!(shares2[0].group_public_key, gpk);

        // Can sign with final shares
        let message = b"double rotated";
        let (n0, c0) = generate_nonces(shares2[0].index, &mut OsRng);
        let (n1, c1) = generate_nonces(shares2[1].index, &mut OsRng);
        let commitments = vec![c0, c1];
        let p0 = sign_partial(&shares2[0], &n0, message, &commitments).unwrap();
        let p1 = sign_partial(&shares2[1], &n1, message, &commitments).unwrap();
        let sig = aggregate(message, &commitments, &[p0, p1]);
        verify(&sig, &gpk, message).unwrap();
    }
}

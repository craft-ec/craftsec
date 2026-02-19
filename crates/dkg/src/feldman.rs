//! Feldman Verifiable Secret Sharing for DKG.
//!
//! Each participant:
//! 1. Generates a random polynomial of degree t-1
//! 2. Computes shares for all other participants
//! 3. Publishes commitments (polynomial coefficients * generator)
//! 4. Other participants verify their shares against commitments
//! 5. Each participant sums all received shares → their key shard
//! 6. Group public key = sum of all constant-term commitments

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::{EdwardsPoint, Scalar};
use craftsec_core::{CraftSecError, KeyShare, ParticipantIndex, Result, ThresholdConfig};
use crate::polynomial::Polynomial;

/// A participant's contribution to the DKG ceremony.
#[derive(Debug, Clone)]
pub struct DkgContribution {
    /// The participant's index.
    pub index: ParticipantIndex,
    /// Commitments: C_j = a_j * G for each coefficient.
    pub commitments: Vec<EdwardsPoint>,
    /// Shares for each other participant: (index, share_value).
    pub shares: Vec<(ParticipantIndex, Scalar)>,
}

/// Run a complete DKG ceremony (simulated — all participants in one process).
/// Returns key shares for each participant.
pub fn run_dkg(
    config: &ThresholdConfig,
    rng: &mut impl rand::RngCore,
) -> Result<Vec<KeyShare>> {
    let t = config.threshold as usize;
    let n = config.total as usize;
    let g = ED25519_BASEPOINT_POINT;

    // Step 1: Each participant generates a polynomial and computes contributions
    let mut contributions = Vec::with_capacity(n);
    for i in 1..=n {
        let poly = Polynomial::random_full(t - 1, rng);

        // Commitments: C_j = a_j * G
        let commitments: Vec<EdwardsPoint> = poly
            .coefficients
            .iter()
            .map(|c| g * c)
            .collect();

        // Shares for each participant: f_i(j) for j in 1..=n
        let shares: Vec<(ParticipantIndex, Scalar)> = (1..=n)
            .map(|j| {
                let x = Scalar::from(j as u64);
                (j as ParticipantIndex, poly.evaluate(&x))
            })
            .collect();

        contributions.push(DkgContribution {
            index: i as ParticipantIndex,
            commitments,
            shares,
        });
    }

    // Step 2: Each participant verifies received shares
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

    // Step 3: Each participant sums their received shares
    let group_public_key: EdwardsPoint = contributions
        .iter()
        .map(|c| c.commitments[0])
        .sum();

    let mut key_shares = Vec::with_capacity(n);
    for i in 1..=n {
        // Sum of all shares received by participant i
        let secret: Scalar = contributions
            .iter()
            .map(|c| c.shares[i - 1].1)
            .sum();

        // Verification shares: Y_j = sum of all commitments evaluated at j
        // Y_j = sum_i( sum_k( a_{i,k} * j^k ) ) * G = secret_j * G
        let verification_shares: Vec<(ParticipantIndex, EdwardsPoint)> = (1..=n)
            .map(|j| {
                let vk: EdwardsPoint = contributions
                    .iter()
                    .map(|c| {
                        // Evaluate commitment polynomial at j
                        let x = Scalar::from(j as u64);
                        let mut result = EdwardsPoint::default();
                        let mut x_power = Scalar::ONE;
                        for commitment in &c.commitments {
                            result += commitment * x_power;
                            x_power *= x;
                        }
                        result
                    })
                    .sum();
                (j as ParticipantIndex, vk)
            })
            .collect();

        key_shares.push(KeyShare {
            index: i as ParticipantIndex,
            secret,
            group_public_key,
            verification_shares,
        });
    }

    Ok(key_shares)
}

/// Verify a share against Feldman commitments.
/// Check: share * G == sum(C_k * index^k) for k = 0..t-1
pub fn verify_share(
    index: ParticipantIndex,
    share: &Scalar,
    commitments: &[EdwardsPoint],
) -> Result<()> {
    let g = ED25519_BASEPOINT_POINT;
    let x = Scalar::from(index as u64);

    // LHS: share * G
    let lhs = g * share;

    // RHS: sum(C_k * x^k)
    let mut rhs = EdwardsPoint::default();
    let mut x_power = Scalar::ONE;
    for commitment in commitments {
        rhs += commitment * x_power;
        x_power *= x;
    }

    if lhs == rhs {
        Ok(())
    } else {
        Err(CraftSecError::InvalidShare(format!(
            "share verification failed for participant {index}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn dkg_2_of_3() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = run_dkg(&config, &mut OsRng).unwrap();
        assert_eq!(shares.len(), 3);
        // All shares should have the same group public key
        assert_eq!(shares[0].group_public_key, shares[1].group_public_key);
        assert_eq!(shares[1].group_public_key, shares[2].group_public_key);
        // Each share's secret * G should match its verification share
        let g = ED25519_BASEPOINT_POINT;
        for share in &shares {
            let computed = g * share.secret;
            let expected = share.verification_shares
                .iter()
                .find(|(idx, _)| *idx == share.index)
                .unwrap()
                .1;
            assert_eq!(computed, expected);
        }
    }

    #[test]
    fn dkg_3_of_5() {
        let config = ThresholdConfig::new(3, 5).unwrap();
        let shares = run_dkg(&config, &mut OsRng).unwrap();
        assert_eq!(shares.len(), 5);
        // All group public keys match
        for s in &shares {
            assert_eq!(s.group_public_key, shares[0].group_public_key);
        }
    }

    #[test]
    fn invalid_share_detected() {
        let g = ED25519_BASEPOINT_POINT;
        let commitments = vec![g * Scalar::from(10u64), g * Scalar::from(20u64)];
        // Wrong share value
        let bad_share = Scalar::from(999u64);
        assert!(verify_share(1, &bad_share, &commitments).is_err());
    }

    #[test]
    fn valid_share_passes() {
        let g = ED25519_BASEPOINT_POINT;
        // Polynomial: f(x) = 10 + 20x
        // f(1) = 30, f(2) = 50
        let commitments = vec![g * Scalar::from(10u64), g * Scalar::from(20u64)];
        assert!(verify_share(1, &Scalar::from(30u64), &commitments).is_ok());
        assert!(verify_share(2, &Scalar::from(50u64), &commitments).is_ok());
    }

    #[test]
    fn shares_reconstruct_secret() {
        // Lagrange interpolation at x=0 should recover the group secret
        let config = ThresholdConfig::new(2, 3).unwrap();
        let shares = run_dkg(&config, &mut OsRng).unwrap();

        // Use shares 1 and 2 to reconstruct
        let s1 = &shares[0];
        let s2 = &shares[1];
        let x1 = Scalar::from(s1.index as u64);
        let x2 = Scalar::from(s2.index as u64);

        // Lagrange coefficients for x=0:
        // l1 = x2 / (x2 - x1), l2 = x1 / (x1 - x2)
        let l1 = x2 * (x2 - x1).invert();
        let l2 = x1 * (x1 - x2).invert();
        let reconstructed = s1.secret * l1 + s2.secret * l2;

        // reconstructed * G should equal group public key
        let g = ED25519_BASEPOINT_POINT;
        assert_eq!(g * reconstructed, shares[0].group_public_key);
    }
}

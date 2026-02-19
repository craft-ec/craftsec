//! Lagrange interpolation coefficients.

use curve25519_dalek::Scalar;
use craftsec_core::ParticipantIndex;

/// Compute the Lagrange coefficient for participant `i` given the set of signer indices.
/// λ_i = ∏_{j ∈ S, j ≠ i} (j / (j - i))
pub fn lagrange_coefficient(i: ParticipantIndex, signer_indices: &[ParticipantIndex]) -> Scalar {
    let x_i = Scalar::from(i as u64);
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for &j in signer_indices {
        if j == i {
            continue;
        }
        let x_j = Scalar::from(j as u64);
        numerator *= x_j;
        denominator *= x_j - x_i;
    }

    numerator * denominator.invert()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lagrange_reconstruction() {
        // f(x) = 5 + 3x (secret = 5)
        // f(1) = 8, f(2) = 11, f(3) = 14
        let s1 = Scalar::from(8u64);
        let s2 = Scalar::from(11u64);

        let indices = &[1u32, 2u32];
        let l1 = lagrange_coefficient(1, indices);
        let l2 = lagrange_coefficient(2, indices);

        let secret = s1 * l1 + s2 * l2;
        assert_eq!(secret, Scalar::from(5u64));
    }
}

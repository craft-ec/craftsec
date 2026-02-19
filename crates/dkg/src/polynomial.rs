//! Polynomial operations over the scalar field.

use curve25519_dalek::scalar::Scalar;
use craftsec_core::scalar_ext::random_scalar;

/// A polynomial of degree `t-1` over the scalar field.
#[derive(Debug, Clone)]
pub struct Polynomial {
    /// Coefficients: a_0, a_1, ..., a_{t-1}
    pub coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Generate a random polynomial of degree `degree` with the given constant term.
    pub fn random(degree: usize, constant: Scalar, rng: &mut impl rand::RngCore) -> Self {
        let mut coefficients = Vec::with_capacity(degree + 1);
        coefficients.push(constant);
        for _ in 0..degree {
            coefficients.push(random_scalar(rng));
        }
        Self { coefficients }
    }

    /// Generate a random polynomial with random constant term.
    pub fn random_full(degree: usize, rng: &mut impl rand::RngCore) -> Self {
        let constant = random_scalar(rng);
        Self::random(degree, constant, rng)
    }

    /// Evaluate polynomial at a scalar point: f(x) = sum(a_i * x^i).
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut result = Scalar::ZERO;
        let mut x_power = Scalar::ONE;
        for coeff in &self.coefficients {
            result += coeff * x_power;
            x_power *= x;
        }
        result
    }

    /// The constant term (the secret).
    pub fn secret(&self) -> &Scalar {
        &self.coefficients[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_constant() {
        let p = Polynomial {
            coefficients: vec![Scalar::from(42u64)],
        };
        assert_eq!(p.evaluate(&Scalar::from(100u64)), Scalar::from(42u64));
    }

    #[test]
    fn evaluate_linear() {
        // f(x) = 3 + 5x
        let p = Polynomial {
            coefficients: vec![Scalar::from(3u64), Scalar::from(5u64)],
        };
        // f(2) = 3 + 10 = 13
        assert_eq!(p.evaluate(&Scalar::from(2u64)), Scalar::from(13u64));
    }

    #[test]
    fn evaluate_quadratic() {
        // f(x) = 1 + 2x + 3x^2
        let p = Polynomial {
            coefficients: vec![
                Scalar::from(1u64),
                Scalar::from(2u64),
                Scalar::from(3u64),
            ],
        };
        // f(3) = 1 + 6 + 27 = 34
        assert_eq!(p.evaluate(&Scalar::from(3u64)), Scalar::from(34u64));
    }
}

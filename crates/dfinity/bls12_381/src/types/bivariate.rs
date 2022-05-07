//! Bivariate Polynomials over `Scalar`.
//!
//! Note: This file is largely based on poly.rs

use super::polynomial::common_traits::zeroize_fr;
use crate::types::bls::random_bls12_381_scalar;
use bls12_381::Scalar;
use rand_core::RngCore;
use std::ops::{AddAssign, MulAssign};
use zeroize::Zeroize;

/// A bivariate polynomial
/// Note: The polynomial terms are: coefficients[i][j] * x^i * y^j
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BivariatePolynomial {
    pub coefficients: Vec<Vec<Scalar>>,
}

impl BivariatePolynomial {
    /// Evaluate the polynomial at x, y
    /// TODO: Use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
    pub fn evaluate_at(&self, x: &Scalar, y: &Scalar) -> Scalar {
        // let mut coefficients = self.coefficients.iter().rev();
        // let first = coefficients.next();
        // match first {
        //     None => Scalar::zero(),
        //     Some(ans) => {
        //         let mut ans: Scalar = *ans;
        //         for coeff in coefficients {
        //             ans.mul_assign(x);
        //             ans.add_assign(coeff);
        //         }
        //         ans
        //     }
        // }

        let mut ans = Scalar::zero();
        for (i, vec) in self.coefficients.clone().iter().enumerate() {
            for (j, coeff) in vec.iter().enumerate() {
                let mut xi = Scalar::one();
                let mut yj = Scalar::one();
                for _ in 0..i {
                    xi.mul_assign(x);
                }
                for _ in 0..j {
                    yj.mul_assign(y);
                }

                ans.add_assign(xi.mul(&yj).mul(coeff));
            }
        }
        ans
    }

    /// Creates a random polynomial.
    pub fn random<R: RngCore>(dimensions: (usize, usize), rng: &mut R) -> Self {
        let coefficients: Vec<Vec<Scalar>> = (0..dimensions.0)
            .map(|_| {
                (0..dimensions.1)
                    .map(|_| random_bls12_381_scalar(rng))
                    .collect::<Vec<_>>()
            })
            .collect();
        BivariatePolynomial { coefficients }
    }
}

impl Zeroize for BivariatePolynomial {
    fn zeroize(&mut self) {
        #[cfg_attr(tarpaulin, skip)]
        for arr in self.coefficients.iter_mut() {
            for fr in arr.iter_mut() {
                zeroize_fr(fr);
            }
        }
    }
}

impl Drop for BivariatePolynomial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

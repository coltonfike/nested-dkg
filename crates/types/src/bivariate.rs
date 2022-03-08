use bls12_381::{G1Projective, G2Affine, G2Projective, Scalar};
use group::Curve;
use ic_crypto_internal_bls12381_common::random_bls12_381_scalar;
use ic_crypto_internal_threshold_sig_bls12381::{
    crypto::{public_key_from_secret_key, x_for_index},
    types::{PublicCoefficients as PC, PublicKey},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::ops::{AddAssign, Mul, MulAssign};

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum Message {
    Shares(
        #[serde(with = "serde_bytes")] Vec<u8>,
        #[serde(with = "serde_bytes")] Vec<u8>,
    ),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coefficients: Vec<Vec<Scalar>>,
}

impl Polynomial {
    pub fn random<R: RngCore>(dimensions: (usize, usize), rng: &mut R) -> Self {
        let coefficients: Vec<Vec<Scalar>> = (0..dimensions.0)
            .map(|_| {
                (0..dimensions.1)
                    .map(|_| random_bls12_381_scalar(rng))
                    .collect::<Vec<_>>()
            })
            .collect();
        Self { coefficients }
    }

    // TODO: Use Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
    pub fn evaluate_at(&self, x: &Scalar, y: &Scalar) -> Scalar {
        let mut ans = Scalar::zero();
        for (i, vec) in self.coefficients.clone().iter().enumerate() {
            for (j, coefficient) in vec.iter().enumerate() {
                let mut xi = Scalar::one();
                let mut yj = Scalar::one();
                for _ in 0..i {
                    xi.mul_assign(x);
                }
                for _ in 0..j {
                    yj.mul_assign(y);
                }

                ans.add_assign(xi.mul(&yj).mul(coefficient));
            }
        }
        ans
    }

    // ! Assumes polynomials are same size
    pub fn add_assign(&mut self, rhs: &Self) {
        for i in 0..self.coefficients.len() {
            for j in 0..self.coefficients[0].len() {
                self.coefficients[i][j] += rhs.coefficients[i][j];
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicCoefficients {
    pub coefficients: Vec<Vec<PublicKey>>,
}

impl PublicCoefficients {
    // TODO: make this auto add 1 and convert to scalar for each x and y
    pub fn evaluate_at(&self, x: &Scalar, y: &Scalar) -> G2Projective {
        let mut ans = self.coefficients[0][0].0;
        for (i, vec) in self.coefficients.clone().iter().enumerate() {
            for (j, coefficient) in vec.iter().enumerate() {
                // skip first iteration since our ans is initially set to first value
                if i == 0 && j == 0 {
                    continue;
                }
                let mut xi = Scalar::one();
                let mut yj = Scalar::one();
                for _ in 0..i {
                    xi.mul_assign(x);
                }
                for _ in 0..j {
                    yj.mul_assign(y);
                }

                ans.add_assign(coefficient.0.mul(xi.mul(&yj)));
            }
        }
        ans
    }

    // ! This assumes both are same size
    pub fn add_assign(&mut self, rhs: &Self) {
        for i in 0..self.coefficients.len() {
            for j in 0..self.coefficients[0].len() {
                self.coefficients[i][j].0 += rhs.coefficients[i][j].0;
            }
        }
    }

    // ! This assumes both are same size
    pub fn add(&self, rhs: &Self) -> Self {
        let mut coefficients = Vec::new();
        for i in 0..self.coefficients.len() {
            let mut internal_coefficients = Vec::new();
            for j in 0..self.coefficients[0].len() {
                internal_coefficients.push(PublicKey(
                    self.coefficients[i][j].0 + rhs.coefficients[i][j].0,
                ));
            }
            coefficients.push(internal_coefficients);
        }
        PublicCoefficients { coefficients }
    }

    pub fn interpolate_g1(samples: &[(Scalar, G1Projective)]) -> Result<G1Projective, String> {
        match PC::interpolate_g1(samples) {
            Ok(res) => Ok(res),
            Err(_) => Err("Failed to interpolate public coefficients".to_string()),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.evaluate_at(&Scalar::zero(), &Scalar::zero()))
    }

    pub fn group_public_key(&self, group_index: u32) -> PublicKey {
        PublicKey(self.evaluate_at(&x_for_index(group_index), &Scalar::zero()))
    }

    pub fn individual_public_key(&self, index: (u32, u32)) -> PublicKey {
        PublicKey(self.evaluate_at(&x_for_index(index.0), &x_for_index(index.1)))
    }
}

// TODO: improve this with iterators
impl From<&Polynomial> for PublicCoefficients {
    fn from(polynomial: &Polynomial) -> Self {
        PublicCoefficients {
            coefficients: {
                let mut coefficients = Vec::new();
                for i in 0..polynomial.coefficients.len() {
                    let mut internal_coefficients = Vec::new();
                    for j in 0..polynomial.coefficients[0].len() {
                        internal_coefficients
                            .push(public_key_from_secret_key(&polynomial.coefficients[i][j]));
                    }
                    coefficients.push(internal_coefficients);
                }
                coefficients
            },
        }
    }
}

impl From<Polynomial> for PublicCoefficients {
    fn from(polynomial: Polynomial) -> Self {
        PublicCoefficients::from(&polynomial)
    }
}

pub struct Dealing(pub PublicCoefficients, pub Vec<Vec<Scalar>>);

impl Dealing {
    pub fn serialize(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.0
                .coefficients
                .iter()
                .flat_map(|coefficient| {
                    coefficient
                        .iter()
                        .flat_map(|coefficient| {
                            coefficient
                                .0
                                .to_affine()
                                .to_uncompressed()
                                .as_ref()
                                .to_vec()
                        })
                        .collect::<Vec<u8>>()
                })
                .collect(),
            self.1
                .iter()
                .flat_map(|scalar| {
                    scalar
                        .iter()
                        .flat_map(|scalar| scalar.to_bytes().to_vec())
                        .collect::<Vec<u8>>()
                })
                .collect(),
        )
    }

    pub fn deserialize(
        coefficients: Vec<u8>,
        scalars: Vec<u8>,
        group_size: usize,
        t_prime: usize,
    ) -> Self {
        Dealing(
            PublicCoefficients {
                coefficients: coefficients
                    .chunks_exact(192)
                    .map(|chunk| {
                        PublicKey(G2Projective::from(
                            &G2Affine::from_uncompressed_unchecked(chunk.try_into().unwrap())
                                .unwrap(),
                        ))
                    })
                    .collect::<Vec<PublicKey>>()
                    .chunks_exact(t_prime)
                    .map(|chunk| chunk.to_vec())
                    .collect(),
            },
            scalars
                .chunks_exact(32)
                .map(|chunk| Scalar::from_bytes(chunk.try_into().unwrap()).unwrap())
                .collect::<Vec<Scalar>>()
                .chunks_exact(group_size)
                .map(|chunk| chunk.to_vec())
                .collect(),
        )
    }
}

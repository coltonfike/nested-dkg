use bls12_381::{G2Affine, G2Projective, Scalar};
use group::Curve;
use ic_crypto_internal_threshold_sig_bls12381::types::{PublicCoefficients, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum Message {
    Shares(Vec<Vec<u8>>, Vec<Vec<u8>>),
}

pub struct Dealing(pub PublicCoefficients, pub Vec<Scalar>);

impl Dealing {
    pub fn serialize(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        (
            self.0
                .coefficients
                .iter()
                .fold(Vec::new(), |mut acc, coefficient| {
                    acc.push(
                        coefficient
                            .0
                            .to_affine()
                            .to_uncompressed()
                            .as_ref()
                            .to_vec(),
                    );
                    acc
                }),
            self.1.iter().fold(Vec::new(), |mut acc, scalar| {
                acc.push(scalar.to_bytes().to_vec());
                acc
            }),
        )
    }

    pub fn deserialize(coefficients: Vec<Vec<u8>>, scalars: Vec<Vec<u8>>) -> Self {
        Dealing(
            PublicCoefficients {
                coefficients: coefficients
                    .iter()
                    .fold(Vec::new(), |mut acc, coefficient| {
                        acc.push(PublicKey(G2Projective::from(
                            &G2Affine::from_uncompressed_unchecked(
                                coefficient
                                    .as_slice()
                                    .try_into()
                                    .expect("Slice for PublicCoefficient is not len 96"),
                            )
                            .unwrap(),
                        )));
                        acc
                    }),
            },
            scalars.iter().fold(Vec::new(), |mut acc, scalar| {
                acc.push(
                    Scalar::from_bytes(
                        scalar
                            .as_slice()
                            .try_into()
                            .expect("Slice for Scalar is not len 32"),
                    )
                    .unwrap(), // unwrap since CtOption doesn't have expect
                );
                acc
            }),
        )
    }
}

use std::{collections::BTreeMap, ops::Add};

use bls12_381::{G1Projective, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::{
    crypto::x_for_index,
    types::{Polynomial, PublicCoefficients, PublicKey},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use types::univariate::Dealing;

pub fn generate_shares(n: u32, t: usize) -> Dealing {
    let seed = rand::random::<[u8; 32]>();
    let mut rng = ChaChaRng::from_seed(seed);
    let poly = Polynomial::random(t, &mut rng);

    let shares = (0..n)
        .map(|i| poly.evaluate_at(&x_for_index(i)))
        .collect::<Vec<Scalar>>();
    let public_coefficients = PublicCoefficients::from(&poly);
    Dealing(public_coefficients, shares)
}

pub fn combine_dealings(index: usize, dealings: &Vec<Dealing>) -> (PublicCoefficients, Scalar) {
    dealings.iter().fold(
        (PublicCoefficients::zero(), Scalar::zero()),
        |(coefficients, shares), dealing| {
            (coefficients.add(&dealing.0), shares.add(dealing.1[index]))
        },
    )
}

pub fn get_public_key(index: usize, coefficients: &PublicCoefficients) -> PublicKey {
    PublicKey(coefficients.evaluate_at(&x_for_index(index as u32)))
}

// TODO: Move this to a sign crate
pub fn combine_signatures(
    signatures: &BTreeMap<usize, G1Projective>,
    t: usize,
) -> Result<G1Projective, String> {
    if signatures.len() < t {
        return Err("Invalid Threshold".to_string());
    }

    let signatures: Vec<(Scalar, G1Projective)> = signatures
        .iter()
        .map(|(k, v)| (x_for_index(*k as u32), *v))
        .collect();
    Ok(PublicCoefficients::interpolate_g1(&signatures).expect("Duplicate indices"))
}

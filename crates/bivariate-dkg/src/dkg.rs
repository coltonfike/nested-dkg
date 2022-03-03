use std::ops::Add;

use bls12_381::{G1Projective, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::crypto::x_for_index;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use types::bivariate::{Dealing, Polynomial, PublicCoefficients};

pub fn generate_shares((n, m): (u32, u32), (t, t_prime): (usize, usize)) -> Dealing {
    let seed = rand::random::<[u8; 32]>();
    let mut rng = ChaChaRng::from_seed(seed);
    let poly = Polynomial::random((t, t_prime), &mut rng);

    let shares = (0..n)
        .map(|i| {
            (0..m)
                .map(|j| poly.evaluate_at(&x_for_index(i), &x_for_index(j)))
                .collect::<Vec<Scalar>>()
        })
        .collect::<Vec<Vec<Scalar>>>();
    let public_coefficients = PublicCoefficients::from(&poly);
    Dealing(public_coefficients, shares)
}

pub fn combine_dealings(
    index: (usize, usize),
    dealings: &Vec<Dealing>,
) -> (PublicCoefficients, Scalar) {
    dealings.iter().skip(1).fold(
        (dealings[0].0.clone(), dealings[0].1[index.0][index.1]),
        |(coefficients, shares), dealing| {
            (
                coefficients.add(&dealing.0),
                shares.add(dealing.1[index.0][index.1]),
            )
        },
    )
}

pub fn combine_signatures(signatures: &[G1Projective], t: usize) -> Result<G1Projective, String> {
    if signatures.len() < t {
        return Err("Invalid Threshold".to_string());
    }

    let signatures: Vec<(Scalar, G1Projective)> = signatures
        .iter()
        .zip(0_u32..)
        .filter_map(|(signature, index)| {
            Some(*signature).map(|signature| (x_for_index(index), signature))
        })
        .collect();
    Ok(PublicCoefficients::interpolate_g1(&signatures).expect("Duplicate indices"))
}

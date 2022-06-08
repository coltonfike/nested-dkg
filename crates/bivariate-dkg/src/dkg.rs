use std::{
    collections::BTreeMap,
    ops::{Add, AddAssign, MulAssign},
};

use bls12_381::{G1Projective, Scalar};
use ic_crypto_internal_threshold_sig_bls12381::crypto::x_for_index;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use types::bivariate::{Dealing, Polynomial, PublicCoefficients};

// generate shares for a dealing
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

// generate shares for nidkg
// this fn includes the intermediate public coefficients
// this could be optimized by doing the generation of the public coefficients at the same time as the share generation
pub fn generate_shares_for_nidkg(
    (n, m): (u32, u32),
    (t, t_prime): (usize, usize),
) -> (Dealing, Vec<Vec<Scalar>>) {
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

    let mut pcs = Vec::new();
    for k in 0..n {
        let mut pcs_k = Vec::new();
        for (_, vec) in poly.coefficients.clone().iter().enumerate() {
            let mut ans = Scalar::zero();
            for (j, coefficient) in vec.iter().enumerate() {
                let mut yj = Scalar::one();
                let value: [u64; 4] = [k as u64, 0, 0, 0];
                let value = Scalar::from_raw(value);
                for _ in 0..j {
                    yj.mul_assign(value);
                }

                ans.add_assign(yj.mul(coefficient));
            }
            pcs_k.push(ans);
        }
        pcs.push(pcs_k);
    }

    (Dealing(public_coefficients, shares), pcs)
}

// combine the dealings by adding shares
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

// TODO: move this to a common crate as this fn is duplicated in univar version
// combine signatures with interpolation,
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

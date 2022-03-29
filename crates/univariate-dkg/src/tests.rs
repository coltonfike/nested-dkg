use std::{collections::BTreeMap, ops::Add};

use bls12_381::G2Projective;
use ic_crypto_internal_threshold_sig_bls12381::{
    crypto::{combined_public_key, sign_message, verify_combined_sig, verify_individual_sig},
    types::{Polynomial, PublicCoefficients, PublicKey},
};
use num::BigInt;
use rand::prelude::SliceRandom;
use types::univariate::{Dealing, Message};

use crate::dkg::*;

#[test]
fn run_11_node_dkg() {
    // let dealings: Vec<Dealing> = (0..11).map(|_| generate_shares(11, 5)).collect();

    // let public_coefficients = dealings
    //     .iter()
    //     .fold(PublicCoefficients::zero(), |acc, dealing| {
    //         acc.add(dealing.0.clone())
    //     });
    // let msg = rand::random::<[u8; 32]>();

    // let mut signatures = Vec::new();
    // for i in 0..11 {
    //     // This continually recalculates the public coefficients, so it shouldn't be used for benchmarking
    //     let (_, sk) = combine_dealings(i, &dealings);
    //     let pk = get_public_key(i, &public_coefficients);
    //     signatures.push(sign_message(&msg, &sk));
    //     verify_individual_sig(&msg, signatures[i], pk).unwrap();
    // }

    // let sig = combine_signatures(signatures.as_slice(), 5).unwrap();
    // verify_combined_sig(&msg, sig, combined_public_key(&public_coefficients)).unwrap();
}

#[test]
fn serialize() {
    let original_dealing = generate_shares(11, 5);
    let (coefficients, scalars) = original_dealing.serialize();
    let original_msg = Message::Shares(coefficients, scalars);
    let msg = bincode::serialize(&original_msg).unwrap();

    let recovered_msg: Message = bincode::deserialize(msg.as_slice()).unwrap();
    assert_eq!(
        original_msg, recovered_msg,
        "Original Message != Recovered Message"
    );

    let recovered_dealing = match recovered_msg {
        Message::Shares(c, s) => Dealing::deserialize(c, s),
    };

    assert_eq!(
        original_dealing.0, recovered_dealing.0,
        "Coefficients do not match"
    );
    assert_eq!(
        original_dealing.1, recovered_dealing.1,
        "Scalars do not match"
    );
}

#[test]
fn prf_eval() {
    let n = 15;
    use bigdecimal::{num_bigint::ToBigInt, BigDecimal};
    use bls12_381::Scalar;
    use openssl::{
        bn::{BigNum, BigNumContext, MsbOption},
        ec::{EcGroup, EcPoint},
        nid::Nid,
        sha::Sha512,
    };

    let x = "colton".to_string();
    let u = 8192;
    let secp256 = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let secp571 = EcGroup::from_curve_name(Nid::SECT571K1).unwrap();
    let secp283 = EcGroup::from_curve_name(Nid::SECT283K1).unwrap();

    let mut ctx = BigNumContext::new().unwrap();

    let p =
        BigNum::from_hex_str("01000000FFFFFFFFFE5BFEFF02A4BD5305D8A10908D83933487D9D2953A7ED73")
            .unwrap();

    let mut q = BigNum::new().unwrap();
    secp283.order(&mut q, &mut ctx).unwrap();

    let mut tau = BigNum::new().unwrap();
    secp571.order(&mut tau, &mut ctx).unwrap();

    let bigdecp = BigDecimal::parse_bytes(p.to_string().as_bytes(), 10).unwrap();
    let bigdecq = BigDecimal::parse_bytes(q.to_string().as_bytes(), 10).unwrap();

    let pqratio = bigdecp / bigdecq;

    let mut keys = BTreeMap::new();

    for i in 0..n {
        let alpha: Vec<BigNum> = (0..u)
            .map(|_| {
                let mut bn = BigNum::new().unwrap();
                bn.rand(283, MsbOption::MAYBE_ZERO, false).unwrap();
                bn
            })
            .collect();

        let mut order = BigNum::new().unwrap();
        secp283.order(&mut order, &mut ctx).unwrap();

        let hashval: Vec<BigNum> = (0..u)
            .map(|i: usize| {
                let mut hasher = Sha512::new();
                hasher.update(x.as_bytes());
                hasher.update(i.to_string().as_bytes());
                let f = hasher.finish();
                &BigNum::from_slice(&f).unwrap() % &order
            })
            .collect();

        let w: BigNum = &alpha
            .iter()
            .zip(hashval.iter())
            .map(|(a, b)| a * b)
            .fold(BigNum::new().unwrap(), |acc, i| &acc + &i)
            % &q;

        let z = {
            let i = (BigDecimal::parse_bytes(w.to_string().as_bytes(), 10).unwrap() * &pqratio)
                .to_bigint()
                .unwrap();
            &BigNum::from_dec_str(&i.to_string()).unwrap() % &p
        };

        let (_, mut z_le_bytes) = BigInt::from_signed_bytes_be(z.to_vec().as_ref()).to_bytes_le();
        while z_le_bytes.len() < 32 {
            z_le_bytes.push(0);
        }

        let sk = Scalar::from_bytes(z_le_bytes.as_slice().try_into().unwrap()).unwrap();
        let pk = G2Projective::generator();
        let pk = pk * sk;

        keys.insert(i, (sk, PublicKey(pk)));
        // (sk, PublicKey(pk))
    }

    let v = vec![Scalar::one().neg(), Scalar::one()];
    let lambda: Vec<Scalar> = (0..n)
        .map(|_| *v.choose(&mut rand::thread_rng()).unwrap())
        .collect();
    // let lambda = vec![Scalar::one(), Scalar::one().neg()];

    let total_sk: Scalar = lambda
        .iter()
        .zip(keys.iter())
        .map(|(lambda, (_, v))| lambda * v.0)
        .sum();

    let total_pk = PublicKey(
        keys.iter()
            .zip(lambda.iter())
            .map(|((_, v), lambda)| G2Projective::generator() * v.0 * lambda)
            .sum(),
    );

    // let whole_pk = PublicKey(keys.iter().map(|(k, v)| v.1 .0).sum());
    let msg: [u8; 32] = [0; 32];
    let mut sigs = BTreeMap::new();

    for (k, v) in keys {
        let my_sig = sign_message(&msg, &v.0);
        verify_individual_sig(&msg, my_sig, v.1).unwrap();
        sigs.insert(k as usize, my_sig);
    }

    let combined_sig = sigs
        .iter()
        .zip(lambda.iter())
        .map(|((_, v), lambda)| v * lambda)
        .sum();
    // combine_signatures(&sigs, 2).unwrap();
    verify_combined_sig(&msg, combined_sig, total_pk).unwrap();

    // let my_sig = sign_message(&msg, &total_sk);
    // verify_individual_sig(&msg, my_sig, total_pk).unwrap();
}

#[test]
pub fn two_points() {
    let dealings: Vec<Dealing> = (0..2).map(|_| generate_shares(2, 2)).collect();

    let public_coefficients = dealings
        .iter()
        .fold(PublicCoefficients::zero(), |acc, dealing| {
            acc.add(dealing.0.clone())
        });
    let msg = rand::random::<[u8; 32]>();

    let mut signatures = BTreeMap::new();
    for i in 0..2 {
        // This continually recalculates the public coefficients, so it shouldn't be used for benchmarking
        let (_, sk) = combine_dealings(i, &dealings);
        let pk = get_public_key(i, &public_coefficients);
        signatures.insert(i, sign_message(&msg, &sk));
        verify_individual_sig(&msg, signatures[&i], pk).unwrap();
    }

    let sig = combine_signatures(&signatures, 2).unwrap();
    verify_combined_sig(&msg, sig, combined_public_key(&public_coefficients)).unwrap();
}

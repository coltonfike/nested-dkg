use std::ops::Add;

use ic_crypto_internal_threshold_sig_bls12381::{
    crypto::{combined_public_key, sign_message, verify_combined_sig, verify_individual_sig},
    types::PublicCoefficients,
};
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

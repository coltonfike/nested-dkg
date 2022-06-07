use crate::dkg::*;
use types::bivariate::{Dealing, Message};

// #[test]
// fn run_121_node_dkg() {
// let dealings: Vec<Dealing> = (0..11).map(|_| generate_shares((11, 11), (3, 5))).collect();

// let public_coefficients = dealings
//     .iter()
//     .skip(1)
//     .fold(dealings[0].0.clone(), |acc, dealing| acc.add(&dealing.0));
// let msg = rand::random::<[u8; 32]>();

// let mut signatures = Vec::new();
// for i in 0..11 {
//     let mut group_signatures = Vec::new();
//     for j in 0..11 {
//         let (_, sk) = combine_dealings((i, j), &dealings);
//         let pk = public_coefficients.individual_public_key((i as u32, j as u32));
//         group_signatures.push(sign_message(&msg, &sk));
//         verify_individual_sig(&msg, group_signatures[j], pk).unwrap();
//     }
//     signatures.push(combine_signatures(group_signatures.as_slice(), 5).unwrap());
//     verify_combined_sig(
//         &msg,
//         signatures[i],
//         public_coefficients.group_public_key(i as u32),
//     )
//     .unwrap();
// }

// let sig = combine_signatures(signatures.as_slice(), 3).unwrap();
// verify_combined_sig(&msg, sig, public_coefficients.public_key()).unwrap();
// }

#[test]
fn serialize() {
    let original_dealing = generate_shares((11, 11), (3, 5));
    let (coefficients, scalars) = original_dealing.serialize();
    let original_msg = Message::Shares(coefficients.clone(), scalars);

    let msg = bincode::serialize(&original_msg).unwrap();

    let recovered_msg: Message = bincode::deserialize(msg.as_slice()).unwrap();
    assert_eq!(
        original_msg, recovered_msg,
        "Original Message != Recovered Message"
    );

    let recovered_dealing = match recovered_msg {
        Message::Shares(c, s) => Dealing::deserialize(c, s, 11, 5),
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

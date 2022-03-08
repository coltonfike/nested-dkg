use std::collections::BTreeMap;

use crate::dkg::{combine_dealings, combine_signatures, generate_shares};

use bls12_381::{G1Affine, G1Projective};
use group::Curve;
use ic_crypto_internal_threshold_sig_bls12381::crypto::{
    sign_message, verify_combined_sig, verify_individual_sig,
};
use networking::Node;
use rand::seq::SliceRandom;
use tokio_stream::StreamExt;
use types::{
    bivariate::{Dealing, Message},
    Id,
};

pub fn write_dealing_to_file(nodes: (u32, u32), threshold: (usize, usize)) {
    let dealing = generate_shares(nodes, threshold);

    std::fs::write(
        "bivariate_shares",
        bincode::serialize(&dealing.serialize()).unwrap(),
    )
    .unwrap();
}

pub async fn run_local_threshold_signature(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
) {
    let mut addresses = BTreeMap::new();
    let mut port = 30000;

    for i in 0..nodes.0 {
        for j in 0..nodes.1 {
            addresses.insert(
                Id::Bivariate(i as usize, j as usize),
                format!("127.0.0.1:{}", port),
            );
            port += 1;
        }
    }

    run_single_node_threshold_signature(my_id, nodes, threshold, addresses).await;
}

pub async fn run_single_node_threshold_signature(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
    addresses: BTreeMap<Id, String>,
) {
    let msg: [u8; 32] = [0; 32];

    let ids = addresses
        .iter()
        .filter_map(|(id, _)| match id {
            Id::Bivariate(i, _) => {
                if *i == my_id.0 {
                    None
                } else {
                    Some(*id)
                }
            }
            _ => None,
        })
        .collect::<Vec<Id>>();

    let group_ids = addresses
        .iter()
        .filter_map(|(id, _)| match id {
            Id::Bivariate(i, j) => {
                if *i == my_id.0 && *j != my_id.1 {
                    Some(*id)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect::<Vec<Id>>();

    let dealing: (Vec<u8>, Vec<u8>) = bincode::deserialize(
        &std::fs::read("bivariate_shares").expect("unable to read share file"),
    )
    .expect("unable to deserialize file");
    let dealing = Dealing::deserialize(dealing.0, dealing.1, nodes.0 as usize, threshold.1);

    let pk = dealing
        .0
        .individual_public_key((my_id.0 as u32, my_id.1 as u32));

    let sk = dealing.1[my_id.0][my_id.1];
    let group_pk = dealing.0.group_public_key(my_id.0 as u32);
    let whole_pk = dealing.0.public_key();

    let mut group_partial_sigs = BTreeMap::new();
    let mut all_group_sigs = BTreeMap::new();

    let mut node = Node::new(addresses, Id::Bivariate(my_id.0, my_id.1)).await;

    let t = std::time::Instant::now();

    let my_sig = sign_message(&msg, &sk);
    // verify_individual_sig(&msg, my_sig, pk).unwrap();

    node.broadcast(&my_sig.to_affine().to_uncompressed(), group_ids)
        .await;

    group_partial_sigs.insert(my_id.1, my_sig);

    while group_partial_sigs.len() < threshold.1 {
        let (id, share) = node.recv.next().await.expect("failed to read message");
        let sig = G1Projective::from(
            G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
        );

        match id {
            Id::Bivariate(i, j) => {
                if i == my_id.0 {
                    // TODO: Should we verify it?
                    // verify_individual_sig(
                    //     &msg,
                    //     sig,
                    //     dealing.0.individual_public_key((i as u32, j as u32)),
                    // )
                    // .unwrap();
                    group_partial_sigs.insert(j, sig);
                } else {
                    if !all_group_sigs.contains_key(&i) {
                        all_group_sigs.insert(i, sig);
                    }
                }
            }
            _ => (),
        }
    }

    let group_sig = combine_signatures(&group_partial_sigs, threshold.1 as usize).unwrap();
    // TODO: Should we verify it?
    // verify_combined_sig(&msg, group_sig, group_pk).unwrap();
    all_group_sigs.insert(my_id.0, group_sig);

    let mut rng = rand::thread_rng();
    let to: Vec<Id> = ids
        .choose_multiple(&mut rng, nodes.0 as usize - 1)
        .map(|e| *e)
        .collect();

    node.broadcast(&group_sig.to_affine().to_uncompressed(), to)
        .await;

    while all_group_sigs.len() < threshold.0 {
        let (id, share) = node.recv.next().await.expect("failed to read message");
        let sig = G1Projective::from(
            G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
        );

        match id {
            Id::Bivariate(i, j) => {
                if i == my_id.0 {
                    // TODO: Should we verify it?
                    // verify_individual_sig(
                    //     &msg,
                    //     sig,
                    //     dealing.0.individual_public_key((i as u32, j as u32)),
                    // )
                    // .unwrap();
                    // group_partial_sigs.insert(j, sig);
                } else {
                    if !all_group_sigs.contains_key(&i) {
                        // TODO: Verify this signature?
                        all_group_sigs.insert(i, sig);
                    }
                }
            }
            _ => (),
        }
    }

    let final_sig = combine_signatures(&all_group_sigs, threshold.0 as usize).unwrap();
    verify_combined_sig(&msg, final_sig, whole_pk).unwrap();

    let total_time = t.elapsed();
    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
    println!("total_time: {:?}", total_time);
}

pub async fn run_local_dkg(my_id: (usize, usize), nodes: (u32, u32), threshold: (usize, usize)) {
    let mut addresses = BTreeMap::new();
    let mut port = 30000;

    for i in 0..nodes.0 {
        for j in 0..nodes.1 {
            addresses.insert(
                Id::Bivariate(i as usize, j as usize),
                format!("127.0.0.1:{}", port),
            );
            port += 1;
        }
    }

    run_single_node_dkg(my_id, nodes, threshold, addresses).await;
}

async fn run_single_node_dkg(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
    addresses: BTreeMap<Id, String>,
) {
    let ids = addresses
        .iter()
        .filter_map(|(id, _)| {
            if Id::Bivariate(my_id.0, my_id.1) == *id {
                None
            } else {
                Some(*id)
            }
        })
        .collect::<Vec<Id>>();

    let group_ids = addresses
        .iter()
        .filter_map(|(id, _)| match id {
            Id::Bivariate(i, j) => {
                if *i == my_id.0 && *j != my_id.1 {
                    Some(*id)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect::<Vec<Id>>();

    let mut node = Node::new(addresses, Id::Bivariate(my_id.0, my_id.1)).await;

    let dealing = generate_shares(nodes, threshold);
    let (serialized_coefficients, serialized_shares) = dealing.serialize();
    let msg = Message::Shares(serialized_coefficients, serialized_shares);

    let mut dealings = vec![dealing];

    node.broadcast(&bincode::serialize(&msg).unwrap(), ids)
        .await;

    // n - 1 since we already know our shares
    for _ in 0..(nodes.0 * nodes.1) - 1 {
        let (_, msg) = node.recv.next().await.expect("failed to read message");

        let t = std::time::Instant::now();
        let msg: Message = bincode::deserialize(&msg).unwrap();
        match msg {
            Message::Shares(serialized_coefficients, serialized_shares) => {
                dealings.push(Dealing::deserialize(
                    serialized_coefficients,
                    serialized_shares,
                    11,
                    5,
                ));
            }
        }
        println!("Time taken to deserialize: {:?}", t.elapsed());
    }

    let (coefficients, sk) = combine_dealings(my_id, &dealings);
    let pk = coefficients.individual_public_key((my_id.0 as u32, my_id.1 as u32));

    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
}

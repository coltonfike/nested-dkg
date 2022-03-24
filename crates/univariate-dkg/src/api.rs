use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Write},
};

use crate::dkg::{combine_dealings, combine_signatures, generate_shares, get_public_key};

use bls12_381::{G1Affine, G1Projective, Scalar};
use group::Curve;
use ic_crypto_internal_threshold_sig_bls12381::{
    crypto::{sign_message, verify_combined_sig},
    types::PublicKey,
};
use networking::Node;
use tokio_stream::StreamExt;
use types::{
    univariate::{Dealing, Message},
    Id,
};

pub fn write_dealing_to_file(nodes: u32, threshold: usize) {
    let dealing = generate_shares(nodes, threshold);

    std::fs::write(
        "univariate_shares",
        bincode::serialize(&dealing.serialize()).unwrap(),
    )
    .unwrap();
}

pub async fn run_local_threshold_signature(my_id: usize, n: u32, t: usize) {
    let mut addresses = BTreeMap::new();
    let mut port = 30000;

    for i in 0..n {
        addresses.insert(Id::Univariate(i as usize), format!("127.0.0.1:{}", port));
        port += 1;
    }

    run_single_node_threshold_signature(my_id, n, t, addresses).await;
}

pub async fn run_aws_threshold_signature(my_id: usize, n: u32, t: usize) {
    let mut addresses = BTreeMap::new();
    let reader = BufReader::new(File::open("addresses").unwrap());
    for (i, line) in reader.lines().enumerate() {
        addresses.insert(Id::Univariate(i), line.unwrap());
    }
    run_single_node_threshold_signature(my_id, n, t, addresses).await;
}

async fn run_single_node_threshold_signature(
    my_id: usize,
    n: u32,
    t: usize,
    addresses: BTreeMap<Id, String>,
) {
    let msg: [u8; 32] = [0; 32];

    let ids = addresses
        .iter()
        .filter_map(|(id, _)| {
            if Id::Univariate(my_id) == *id {
                None
            } else {
                Some(*id)
            }
        })
        .collect::<Vec<Id>>();

    let dealing: (Vec<Vec<u8>>, Vec<Vec<u8>>) = bincode::deserialize(
        &std::fs::read("univariate_shares").expect("unable to read share file"),
    )
    .expect("unable to deserialize file");
    let dealing = Dealing::deserialize(dealing.0, dealing.1);

    let pk = get_public_key(my_id, &dealing.0);

    let sk = dealing.1[my_id];
    let whole_pk = dealing.0.evaluate_at(&Scalar::zero());

    let mut partial_sigs = BTreeMap::new();

    let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

    let time = std::time::Instant::now();

    let my_sig = sign_message(&msg, &sk);
    // verify_individual_sig(&msg, my_sig, pk).unwrap();

    node.broadcast(&my_sig.to_affine().to_uncompressed(), ids)
        .await;

    partial_sigs.insert(my_id, my_sig);

    while partial_sigs.len() < t {
        let (id, share) = node.recv.next().await.expect("failed to read message");
        let sig = G1Projective::from(
            G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
        );

        match id {
            Id::Univariate(i) => {
                // TODO: Should we verify it?
                // verify_individual_sig(
                //     &msg,
                //     sig,
                //     dealing.0.individual_public_key((i as u32, j as u32)),
                // )
                // .unwrap();
                partial_sigs.insert(i, sig);
            }
            _ => (),
        }
    }

    let group_sig = combine_signatures(&partial_sigs, t as usize).unwrap();
    // TODO: Should we verify it?
    verify_combined_sig(&msg, group_sig, PublicKey(whole_pk)).unwrap();

    let total_time = time.elapsed();
    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
    println!("total_time: {:?}", total_time);

    let filename = format!("results/univariate_threshold_signatures_{}_{}", n, t);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();
    file.write_all(format!("{:?}\n", total_time).as_bytes())
        .unwrap();
}

pub async fn run_local_dkg(my_id: usize, n: u32, t: usize) {
    let mut addresses = BTreeMap::new();
    let mut port = 30000;

    for i in 0..n {
        addresses.insert(Id::Univariate(i as usize), format!("127.0.0.1:{}", port));
        port += 1;
    }

    run_single_node(my_id, n, t, addresses).await;
}

async fn run_single_node(my_id: usize, n: u32, t: usize, addresses: BTreeMap<Id, String>) {
    let ids = addresses
        .iter()
        .filter_map(|(id, _)| {
            if Id::Univariate(my_id) == *id {
                None
            } else {
                Some(*id)
            }
        })
        .collect::<Vec<Id>>();
    let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

    let dealing = generate_shares(n, t);
    let (serialized_coefficients, serialized_shares) = dealing.serialize();
    let msg = Message::Shares(serialized_coefficients, serialized_shares);

    let mut dealings = vec![dealing];

    node.broadcast(&bincode::serialize(&msg).unwrap(), ids)
        .await;

    // n - 1 since we already know our shares
    for _ in 0..n - 1 {
        let (_, msg) = node.recv.next().await.expect("failed to read message");
        let msg: Message = bincode::deserialize(&msg).unwrap();
        match msg {
            Message::Shares(serialized_coefficients, serialized_shares) => {
                dealings.push(Dealing::deserialize(
                    serialized_coefficients,
                    serialized_shares,
                ));
            }
        }
    }

    let (coefficients, sk) = combine_dealings(my_id, &dealings);
    let pk = get_public_key(my_id, &coefficients);

    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();

    println!("Node {} finished", my_id);
}

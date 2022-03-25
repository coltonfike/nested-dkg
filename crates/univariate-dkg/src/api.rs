use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Write},
};

use crate::dkg::{combine_dealings, combine_signatures, generate_shares, get_public_key};

use bls12_381::{G1Affine, G1Projective, Scalar};
use group::Curve;
use ic_crypto_internal_threshold_sig_bls12381::{
    crypto::{sign_message, verify_combined_sig, verify_individual_sig},
    types::PublicKey,
};
use networking::Node;
use rand::RngCore;
use tokio_stream::StreamExt;
use types::{
    univariate::{Dealing, Message},
    Id,
};

const NUM_THREADS: u32 = 4;

pub fn write_dealing_to_file(nodes: u32, threshold: usize) {
    let dealing = generate_shares(nodes, threshold);

    std::fs::write(
        "univariate_shares",
        bincode::serialize(&dealing.serialize()).unwrap(),
    )
    .unwrap();

    let messages: Vec<Vec<u8>> = (0..100)
        .map(|_| {
            let mut msg: [u8; 64] = [0; 64];
            rand::thread_rng().fill_bytes(&mut msg);
            msg.to_vec()
        })
        .collect();
    std::fs::write("messages", bincode::serialize(&messages).unwrap()).unwrap();
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
    let messages: Vec<[u8; 64]> = {
        let messages: Vec<Vec<u8>> =
            bincode::deserialize(&std::fs::read("messages").expect("failed to read message file"))
                .expect("unable to deserialize file");
        messages
            .iter()
            .map(|v| v.clone().try_into().unwrap())
            .collect()
    };

    let dealing: (Vec<Vec<u8>>, Vec<Vec<u8>>) = bincode::deserialize(
        &std::fs::read("univariate_shares").expect("unable to read share file"),
    )
    .expect("unable to deserialize file");
    let dealing = Dealing::deserialize(dealing.0, dealing.1);

    if my_id == n as usize {
        let mut signatures = BTreeMap::new();
        for (i, _) in messages.iter().enumerate() {
            signatures.insert(i, BTreeMap::new());
        }
        let whole_pk = dealing.0.evaluate_at(&Scalar::zero());

        let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

        let time = std::time::Instant::now();

        while signatures.len() > 0 {
            let (id, share) = node.recv.next().await.expect("failed to read message");
            let (msg, share): (usize, Vec<u8>) = bincode::deserialize(&share).unwrap();
            let sig = G1Projective::from(
                G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
            );

            match id {
                Id::Univariate(i) => {
                    if signatures.contains_key(&msg) {
                        verify_individual_sig(&messages[msg], sig, get_public_key(i, &dealing.0))
                            .unwrap();
                        let group = signatures.get_mut(&msg).unwrap();
                        group.insert(i, sig);
                        if group.len() >= t {
                            let group_sig = combine_signatures(group, t as usize).unwrap();
                            verify_combined_sig(&messages[msg], group_sig, PublicKey(whole_pk))
                                .unwrap();
                            signatures.remove(&msg);
                        }
                    }
                }
                _ => (),
            }
        }

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
    } else {
        let ids = vec![Id::Univariate(n as usize)];

        let sk = dealing.1[my_id];

        let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

        for (i, msg) in messages.iter().enumerate() {
            let my_sig = sign_message(msg, &sk);
            let to_send = (i, &my_sig.to_affine().to_uncompressed().to_vec());

            node.broadcast(&bincode::serialize(&to_send).unwrap(), ids.clone())
                .await;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        node.shutdown();
    }
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

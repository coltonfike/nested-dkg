use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Write},
};

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

// write dealing for threshold signatures
pub fn write_dealing_to_file(nodes: (u32, u32), threshold: (usize, usize)) {
    let dealing = generate_shares(nodes, threshold);

    std::fs::write(
        "bivariate_shares",
        bincode::serialize(&dealing.serialize()).unwrap(),
    )
    .unwrap();
}

// setup for threshold signatures
pub async fn run_threshold_signature(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
    aws: bool,
) {
    let addresses = {
        let mut addresses = BTreeMap::new();
        if aws {
            let mut reader = BufReader::new(File::open("addresses").unwrap());

            for i in 0..nodes.0 {
                for j in 0..nodes.1 {
                    let mut addr = String::new();
                    reader.read_line(&mut addr).unwrap();
                    addr.pop();
                    addresses.insert(Id::Bivariate(i as usize, j as usize), addr);
                }
            }
        } else {
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
        }
        addresses
    };

    run_single_node_threshold_signature(my_id, nodes, threshold, addresses).await;
}

// run threshold signature
pub async fn run_single_node_threshold_signature(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
    addresses: BTreeMap<Id, String>,
) {
    let msg: [u8; 32] = [0; 32];

    // ids of all nodes not in this group
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

    // ids of nodes in this group
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

    // read dealing and compute keys
    let dealing: (Vec<u8>, Vec<u8>) = bincode::deserialize(
        &std::fs::read("bivariate_shares").expect("unable to read share file"),
    )
    .expect("unable to deserialize file");
    let dealing = Dealing::deserialize(dealing.0, dealing.1, nodes.1 as usize, threshold.1);

    let pk = dealing
        .0
        .individual_public_key((my_id.0 as u32, my_id.1 as u32));

    let sk = dealing.1[my_id.0][my_id.1];
    let group_pk = dealing.0.group_public_key(my_id.0 as u32);
    let whole_pk = dealing.0.public_key();

    let mut group_partial_sigs = BTreeMap::new();
    let mut all_group_sigs = BTreeMap::new();

    let mut node = Node::new(addresses, Id::Bivariate(my_id.0, my_id.1)).await;

    let time = std::time::Instant::now();
    let t = std::time::Instant::now();

    // sign and verify
    let my_sig = sign_message(&msg, &sk);
    let sign_time = t.elapsed();
    let t = std::time::Instant::now();
    verify_individual_sig(&msg, my_sig, pk).unwrap();
    let verify_time = t.elapsed();

    node.broadcast(&my_sig.to_affine().to_uncompressed(), group_ids)
        .await;

    group_partial_sigs.insert(my_id.1, my_sig);

    // wait for t' sigs from group
    while group_partial_sigs.len() < threshold.1 {
        let (id, share) = node.recv.next().await.expect("failed to read message");
        let sig = G1Projective::from(
            G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
        );

        // verify the signature
        match id {
            Id::Bivariate(i, j) => {
                if i == my_id.0 {
                    verify_individual_sig(
                        &msg,
                        sig,
                        dealing.0.individual_public_key((i as u32, j as u32)),
                    )
                    .unwrap();
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

    // combine the group signature and verify it
    let t = std::time::Instant::now();
    let group_sig = combine_signatures(&group_partial_sigs, threshold.1 as usize).unwrap();
    let combine_time_group = t.elapsed();
    let t = std::time::Instant::now();
    verify_combined_sig(&msg, group_sig, group_pk).unwrap();
    let verify_combined_time = t.elapsed();
    all_group_sigs.insert(my_id.0, group_sig);

    // randomly select n log n nodes to broadcast the group signature
    let mut rng = rand::thread_rng();
    let selection = nodes.1 * (((nodes.1 as f64).log(10.0) as u32) + 1);
    let to: Vec<Id> = ids
        .choose_multiple(&mut rng, selection as usize)
        .map(|e| *e)
        .collect();
    node.broadcast(&group_sig.to_affine().to_uncompressed(), to)
        .await;

    // wait for t sigs from all nodes
    while all_group_sigs.len() < threshold.0 {
        let (id, share) = node.recv.next().await.expect("failed to read message");
        let sig = G1Projective::from(
            G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
        );

        match id {
            Id::Bivariate(i, j) => {
                if i == my_id.0 {
                    group_partial_sigs.insert(j, sig);
                } else {
                    if !all_group_sigs.contains_key(&i) {
                        verify_individual_sig(&msg, sig, dealing.0.group_public_key(i as u32))
                            .unwrap();
                        all_group_sigs.insert(i, sig);
                    }
                }
            }
            _ => (),
        }
    }

    // combine and verify the final signatures
    let t = std::time::Instant::now();
    let final_sig = combine_signatures(&all_group_sigs, threshold.0 as usize).unwrap();
    let combined_time = t.elapsed();
    let t = std::time::Instant::now();
    verify_combined_sig(&msg, final_sig, whole_pk).unwrap();
    let verify_total_time = t.elapsed();

    // shutdown and record results
    let total_time = time.elapsed();
    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
    println!("total_time: {:?}", total_time);
    let filename = format!(
        "results/bivariate_threshold_signatures_{},{}_{},{}",
        nodes.0, nodes.1, threshold.0, threshold.1
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();

    file.write_all(
        format!(
            "{:?},{:?},{:?},{:?},{:?},{:?},{:?}\n",
            total_time,
            sign_time,
            verify_time,
            combine_time_group,
            verify_combined_time,
            combined_time,
            verify_total_time
        )
        .as_bytes(),
    )
    .unwrap();
}

// setup to run the dkg
pub async fn run_dkg(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
    aws: bool,
) {
    let addresses = {
        let mut addresses = BTreeMap::new();
        if aws {
            let mut reader = BufReader::new(File::open("addresses").unwrap());

            for i in 0..nodes.0 {
                for j in 0..nodes.1 {
                    let mut addr = String::new();
                    reader.read_line(&mut addr).unwrap();
                    addr.pop();
                    addresses.insert(Id::Bivariate(i as usize, j as usize), addr);
                }
            }
        } else {
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
        }
        addresses
    };

    run_single_node_dkg(my_id, nodes, threshold, addresses).await;
}

// run dkg
async fn run_single_node_dkg(
    my_id: (usize, usize),
    nodes: (u32, u32),
    threshold: (usize, usize),
    addresses: BTreeMap<Id, String>,
) {
    // ids of all nodes
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

    // ids of my group
    let _group_ids = addresses
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

    // generate dealing and send it to all nodes
    let time = std::time::Instant::now();
    let t = std::time::Instant::now();
    let dealing = generate_shares(nodes, threshold);
    let generate_shares_time = t.elapsed();
    let (serialized_coefficients, serialized_shares) = dealing.serialize();
    let msg = Message::Shares(serialized_coefficients, serialized_shares);

    let mut dealings = vec![dealing];

    node.broadcast(&bincode::serialize(&msg).unwrap(), ids)
        .await;

    // wait for all nodes to send dealing
    for _ in 0..(nodes.0 * nodes.1) - 1 {
        let (_, msg) = node.recv.next().await.expect("failed to read message");

        let _t = std::time::Instant::now();
        let msg: Message = bincode::deserialize(&msg).unwrap();
        // TODO: Verify dealing
        match msg {
            Message::Shares(serialized_coefficients, serialized_shares) => {
                dealings.push(Dealing::deserialize(
                    serialized_coefficients,
                    serialized_shares,
                    nodes.1 as usize,
                    threshold.1,
                ));
            }
        }
    }

    // extract the keys
    let t = std::time::Instant::now();
    let (coefficients, _sk) = combine_dealings(my_id, &dealings);
    let combined_time = t.elapsed();
    let _pk = coefficients.individual_public_key((my_id.0 as u32, my_id.1 as u32));

    let msg: [u8; 32] = [0; 32];
    let t = std::time::Instant::now();
    let my_sig = sign_message(&msg, &_sk);
    verify_individual_sig(&msg, my_sig, _pk).unwrap();
    let sign_time = t.elapsed();

    // shutdown and record results
    let total_time = time.elapsed();
    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
    println!("total_time: {:?}", total_time);
    let filename = format!(
        "results/bivariate_dkg_{},{}_{},{}",
        nodes.0, nodes.1, threshold.0, threshold.1
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();

    file.write_all(
        format!(
            "{:?},{:?},{:?},{:?}\n",
            total_time, generate_shares_time, combined_time, sign_time,
        )
        .as_bytes(),
    )
    .unwrap();
}

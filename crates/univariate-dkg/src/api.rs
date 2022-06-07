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
use tokio_stream::StreamExt;
use types::{
    univariate::{Dealing, Message},
    Id,
};

// Generates shares and writes them to a file. Useful for tests that assume shares already exist
pub fn write_dealing_to_file(nodes: u32, threshold: usize) {
    let dealing = generate_shares(nodes, threshold);

    std::fs::write(
        "univariate_shares",
        bincode::serialize(&dealing.serialize()).unwrap(),
    )
    .unwrap();
}

// Runs a node for threshold signatures
pub async fn run_threshold_signature(my_id: usize, n: u32, t: usize, aws: bool) {
    let addresses = {
        let mut addresses = BTreeMap::new();
        if aws {
            let reader = BufReader::new(File::open("addresses").unwrap());
            for (i, line) in reader.lines().enumerate() {
                addresses.insert(Id::Univariate(i), line.unwrap());
            }
        } else {
            let mut port = 30000;
            for i in 0..n {
                addresses.insert(Id::Univariate(i as usize), format!("127.0.0.1:{}", port));
                port += 1;
            }
        }
        addresses
    };

    run_single_node_threshold_signature(my_id, n, t, addresses).await;
}

// runs a node for a threshold signature
async fn run_single_node_threshold_signature(
    my_id: usize,
    n: u32,
    t: usize,
    addresses: BTreeMap<Id, String>,
) {
    // static msg to sign
    let msg: [u8; 32] = [0; 32];

    // node ids that we will send messages to
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

    // read our shares from a file
    let dealing: (Vec<Vec<u8>>, Vec<Vec<u8>>) = bincode::deserialize(
        &std::fs::read("univariate_shares").expect("unable to read share file"),
    )
    .expect("unable to deserialize file");
    let dealing = Dealing::deserialize(dealing.0, dealing.1);

    // get our public key
    let _pk = get_public_key(my_id, &dealing.0);

    // get our secret key
    let sk = dealing.1[my_id];

    // get the group public key
    let whole_pk = dealing.0.evaluate_at(&Scalar::zero());

    let mut partial_sigs = BTreeMap::new();

    let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

    let time = std::time::Instant::now();
    let verify_time;
    let sign_time;

    // sign my message and broadcast it
    let t1 = std::time::Instant::now();
    let my_sig = sign_message(&msg, &sk);
    sign_time = t1.elapsed();
    let t1 = std::time::Instant::now();
    verify_individual_sig(&msg, my_sig, _pk).unwrap();
    verify_time = t1.elapsed();

    // we convert the sig to bytes for the sending with to_affine().to_uncompressed()
    // the to_bytes uses the compressed version which is really slow
    node.broadcast(&my_sig.to_affine().to_uncompressed(), ids)
        .await;

    partial_sigs.insert(my_id, my_sig);

    // wait for t signatures
    while partial_sigs.len() < t {
        let (id, share) = node.recv.next().await.expect("failed to read message");

        // deserialize the signature
        let sig = G1Projective::from(
            G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
        );

        match id {
            Id::Univariate(i) => {
                // verify the signature
                verify_individual_sig(&msg, sig, get_public_key(i, &dealing.0)).unwrap();
                partial_sigs.insert(i, sig);
            }
            _ => (),
        }
    }

    // combine and verify the signatures
    let t1 = std::time::Instant::now();
    let group_sig = combine_signatures(&partial_sigs, t as usize).unwrap();
    let aggregate_time = t1.elapsed();
    let t1 = std::time::Instant::now();
    verify_combined_sig(&msg, group_sig, PublicKey(whole_pk)).unwrap();
    let verify_combined_time = t1.elapsed();

    // shutdown and record results
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

    file.write_all(
        format!(
            "{:?},{:?},{:?},{:?},{:?}\n",
            total_time, sign_time, verify_time, aggregate_time, verify_combined_time
        )
        .as_bytes(),
    )
    .unwrap();
}

// runs a dkg test
pub async fn run_dkg(my_id: usize, n: u32, t: usize, aws: bool) {
    let addresses = {
        let mut addresses = BTreeMap::new();
        if aws {
            let reader = BufReader::new(File::open("addresses").unwrap());
            for (i, line) in reader.lines().enumerate() {
                addresses.insert(Id::Univariate(i), line.unwrap());
            }
        } else {
            let mut port = 30000;
            for i in 0..n {
                addresses.insert(Id::Univariate(i as usize), format!("127.0.0.1:{}", port));
                port += 1;
            }
        }
        addresses
    };

    run_single_node(my_id, n, t, addresses).await;
}

// runs a single node in a dkg
async fn run_single_node(my_id: usize, n: u32, t: usize, addresses: BTreeMap<Id, String>) {
    // ids we will send messages to
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

    // generate a dealing and broadcast them
    let time = std::time::Instant::now();
    let t1 = std::time::Instant::now();
    let dealing = generate_shares(n, t);
    let generate_shares_time = t1.elapsed();
    let (serialized_coefficients, serialized_shares) = dealing.serialize();
    let msg = Message::Shares(serialized_coefficients, serialized_shares);

    let mut dealings = vec![dealing];

    node.broadcast(&bincode::serialize(&msg).unwrap(), ids)
        .await;

    // wait for dealings from all other nodes n - 1 since we already know our shares
    for _ in 0..n - 1 {
        let (_, msg) = node.recv.next().await.expect("failed to read message");
        let msg: Message = bincode::deserialize(&msg).unwrap();
        match msg {
            //TODO verify the dealing
            Message::Shares(serialized_coefficients, serialized_shares) => {
                dealings.push(Dealing::deserialize(
                    serialized_coefficients,
                    serialized_shares,
                ));
            }
        }
    }

    // get our public/private key from the dealings
    let t1 = std::time::Instant::now();
    let (coefficients, _sk) = combine_dealings(my_id, &dealings);
    let combined_dealings_time = t1.elapsed();
    let _pk = get_public_key(my_id, &coefficients);

    let msg: [u8; 32] = [0; 32];
    let t1 = std::time::Instant::now();
    let my_sig = sign_message(&msg, &_sk);
    verify_individual_sig(&msg, my_sig, _pk).unwrap();
    let sign_time = t1.elapsed();

    // finish and record results
    let total_time = time.elapsed();
    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
    println!("total_time: {:?}", total_time);

    let filename = format!("results/univariate_dkg_{}_{}", n, t);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();

    file.write_all(
        format!(
            "{:?},{:?},{:?},{:?}\n",
            total_time, generate_shares_time, combined_dealings_time, sign_time,
        )
        .as_bytes(),
    )
    .unwrap();
}

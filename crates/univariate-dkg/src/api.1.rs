use num::bigint::Sign;
use num::BigInt;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Write},
};

use crate::dkg::{combine_dealings, combine_signatures, generate_shares, get_public_key};

use bls12_381::{G1Affine, G1Projective, G2Projective, Scalar};
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

const NUM_THREADS: u32 = 16;

pub fn write_dealing_to_file(nodes: u32, threshold: usize) {
    let dealing = generate_shares(nodes, threshold);

    std::fs::write(
        "univariate_shares",
        bincode::serialize(&dealing.serialize()).unwrap(),
    )
    .unwrap();

    let messages: Vec<Vec<u8>> = (0..10000)
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
        let whole_pk = dealing.0.evaluate_at(&Scalar::zero());

        let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

        let mut threads: Vec<std::sync::mpsc::SyncSender<(Id, usize, Vec<u8>)>> = Vec::new();

        let (ts, signal) = std::sync::mpsc::sync_channel(NUM_THREADS as usize);

        let range_size = messages.len() / NUM_THREADS as usize;
        let mut idx = 0;

        for i in 0..NUM_THREADS {
            let thread_messages = if i == NUM_THREADS - 1 {
                messages[idx..].to_vec()
            } else {
                messages[idx..idx + range_size].to_vec()
            };
            let thread_dealing = dealing.clone();

            let (tx, rx) = std::sync::mpsc::sync_channel(messages.len() * n as usize);
            let thread_signal = ts.clone();
            threads.push(tx);

            std::thread::spawn(move || {
                let mut signatures = BTreeMap::new();
                for (i, _) in thread_messages.iter().enumerate() {
                    signatures.insert(i, BTreeMap::new());
                }

                while signatures.len() > 0 {
                    let (id, msg, share) = rx.recv().unwrap();

                    let sig = G1Projective::from(
                        G1Affine::from_uncompressed_unchecked(&share.try_into().unwrap()).unwrap(),
                    );

                    match id {
                        Id::Univariate(i) => {
                            if signatures.contains_key(&msg) {
                                verify_individual_sig(
                                    &thread_messages[msg],
                                    sig,
                                    get_public_key(i, &thread_dealing.0),
                                )
                                .unwrap();
                                let group = signatures.get_mut(&msg).unwrap();
                                group.insert(i, sig);
                                if group.len() >= t {
                                    let group_sig = combine_signatures(group, t as usize).unwrap();
                                    verify_combined_sig(
                                        &thread_messages[msg],
                                        group_sig,
                                        PublicKey(whole_pk),
                                    )
                                    .unwrap();
                                    signatures.remove(&msg);
                                }
                            }
                        }
                        _ => (),
                    }
                }
                thread_signal.send(0).unwrap();
            });
            idx += range_size;
        }

        let mut signals = 0;
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));
        let time = std::time::Instant::now();

        while signals < NUM_THREADS {
            tokio::select! {
                _ = interval.tick() => {
                    if signal.try_recv().is_ok() {
                        signals += 1;
                        continue;
                    }
                }
                msg = node.recv.next() => {
                    let (id, share) = msg.unwrap();
                    let (msg, share): (usize, Vec<u8>) = bincode::deserialize(&share).unwrap();

                    let mut idx = 0;
                    for i in 0..NUM_THREADS {
                        if msg < idx + range_size {
                            threads[i as usize]
                                .send((id, msg - (i as usize * range_size), share))
                                .map_err(|_| ())
                                .unwrap();
                            break;
                        }
                        idx += range_size;
                    }
                }
            }
        }

        let total_time = time.elapsed();
        std::thread::sleep(std::time::Duration::from_secs(1));
        node.shutdown();
        println!("total_time: {:?}", total_time.as_secs_f64());

        let filename = format!("results/univariate_threshold_signatures_{}_{}", n, t);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(filename)
            .unwrap();
        file.write_all(format!("{:?}\n", total_time.as_secs_f64()).as_bytes())
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

pub fn prf_keygen() -> (Scalar, PublicKey) {
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

    (sk, PublicKey(pk))
    // let msg: [u8; 32] = [0; 32];
    // let my_sig = sign_message(&msg, &sk);
    // verify_individual_sig(&msg, my_sig, PublicKey(pk)).unwrap();
}

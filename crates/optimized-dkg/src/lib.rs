use ic_crypto_internal_threshold_sig_bls12381::ni_dkg::groth20_bls12_381::{
    compute_threshold_signing_key, create_dealing, create_forward_secure_key_pair,
    create_transcript, trusted_secret_key_into_miracl,
    types::{FsEncryptionKeySetWithPop, FsEncryptionSecretKey},
    verify_dealing,
};
use ic_crypto_internal_types::{
    encrypt::forward_secure::groth20_bls12_381::FsEncryptionPublicKey,
    sign::threshold_sig::ni_dkg::{
        ni_dkg_groth20_bls12_381::{Dealing, Transcript},
        Epoch,
    },
};
use ic_types::{
    crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet},
    Height, NumberOfNodes, PrincipalId, Randomness, SubnetId,
};
use networking::Node;
use rand::Rng;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
};
use std::{fs::File, time::Instant};
use tokio_stream::StreamExt;
use types::Id;

pub fn generate_keypairs(n: usize) {
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[2u8, 8u8, 1u8, 2u8];

    let mut keypairs = Vec::new();
    for i in 0..n {
        keypairs.push(create_forward_secure_key_pair(
            Randomness::from(rand::thread_rng().gen::<[u8; 32]>()),
            KEY_GEN_ASSOCIATED_DATA,
        ));
    }

    std::fs::write("keypairs", bincode::serialize(&keypairs).unwrap()).unwrap();
}

pub async fn run_dkg(my_id: usize, n: usize, d: usize, t: usize, is_dealer: bool, aws: bool) {
    let addresses = {
        let mut addresses = BTreeMap::new();
        if aws {
            let reader = BufReader::new(File::open("addresses").unwrap());
            for (i, line) in reader.lines().enumerate() {
                addresses.insert(Id::Univariate(i), line.unwrap());
            }
        } else {
            let mut port = 30000;
            for i in 0..n + d {
                addresses.insert(Id::Univariate(i as usize), format!("127.0.0.1:{}", port));
                port += 1;
            }
        }
        addresses
    };

    let keypairs: Vec<FsEncryptionKeySetWithPop> =
        bincode::deserialize(&std::fs::read("keypairs").expect("unable to read keypairs"))
            .expect("unable to deserialize file");

    let mut receiver_keys = BTreeMap::new();
    for (i, keypair) in keypairs.iter().enumerate() {
        receiver_keys.insert(i as u32, keypair.public_key);
    }

    if is_dealer {
        run_single_dealer(my_id, n, d, t, receiver_keys, addresses).await;
    } else {
        println!("starting receiver");
        run_single_node(
            my_id,
            n,
            d,
            t,
            keypairs[my_id].secret_key.clone(),
            addresses,
        )
        .await;
    }
}

async fn run_single_dealer(
    my_id: usize,
    n: usize,
    d: usize,
    t: usize,
    receiver_keys: BTreeMap<u32, FsEncryptionPublicKey>,
    addresses: BTreeMap<Id, String>,
) {
    //! this is required to generate dealing, but it is not used for any computation, so it's set to default values define by dfinity
    let nidkg_id: NiDkgId = NiDkgId {
        start_block_height: Height::new(3),
        dealer_subnet: SubnetId::new(PrincipalId::new(
            10,
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0,
            ],
        )),
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new([42; 32])),
    };

    let epoch = Epoch::from(1);

    let ids = addresses
        .iter()
        .filter_map(|(id, _)| {
            if Id::Univariate(n) <= *id {
                None
            } else {
                Some(*id)
            }
        })
        .collect::<Vec<Id>>();

    let dealers = addresses
        .iter()
        .filter_map(|(id, _)| {
            if Id::Univariate(n) > *id || Id::Univariate(my_id + n) == *id {
                None
            } else {
                Some(*id)
            }
        })
        .collect::<Vec<Id>>();

    let keygen_seed = Randomness::from(rand::thread_rng().gen::<[u8; 32]>());
    let encryption_seed = Randomness::from(rand::thread_rng().gen::<[u8; 32]>());
    let threshold = NumberOfNodes::new(t as u32);

    let mut dealings = BTreeMap::new();

    let mut node = Node::new(addresses, Id::Univariate(my_id + n)).await;

    let dealing = create_dealing(
        keygen_seed,
        encryption_seed,
        threshold,
        &receiver_keys,
        epoch,
        my_id as u32,
        None,
    )
    .unwrap();

    dealings.insert(my_id as u32, dealing);

    node.broadcast(
        bincode::serialize(dealings.get(&(my_id as u32)).unwrap())
            .unwrap()
            .as_slice(),
        dealers,
    )
    .await;

    while dealings.len() < d {
        let (id, msg) = node.recv.next().await.expect("failed to read message");
        match id {
            Id::Univariate(id) => {
                if !dealings.contains_key(&((id - n) as u32)) {
                    let dealing: Dealing = bincode::deserialize(&msg).unwrap();
                    verify_dealing(
                        nidkg_id,
                        (id - n) as u32,
                        threshold,
                        epoch,
                        &receiver_keys,
                        &dealing,
                    )
                    .unwrap();
                    dealings.insert((id - n) as u32, dealing);
                }
            }
            _ => (),
        }
    }

    let transcript = create_transcript(threshold, NumberOfNodes::new(n as u32), &dealings).unwrap();

    node.broadcast(bincode::serialize(&transcript).unwrap().as_slice(), ids)
        .await;
    std::thread::sleep(std::time::Duration::from_secs(20));
    node.shutdown();
    println!("dealer done");
}

async fn run_single_node(
    my_id: usize,
    n: usize,
    d: usize,
    t: usize,
    sk: FsEncryptionSecretKey,
    addresses: BTreeMap<Id, String>,
) {
    let mut node = Node::new(addresses, Id::Univariate(my_id)).await;
    println!("waiting for transcript");
    let (_, msg) = node.recv.next().await.expect("failed to read message");
    println!("got transcript");
    let transcript: Transcript = bincode::deserialize(&msg).unwrap();

    let signing_key = compute_threshold_signing_key(
        &transcript,
        my_id as u32,
        &trusted_secret_key_into_miracl(&sk),
        Epoch::from(1),
    )
    .unwrap();
    println!("got my signing key");

    std::thread::sleep(std::time::Duration::from_secs(20));
    node.shutdown();
    println!("receiver done");
}

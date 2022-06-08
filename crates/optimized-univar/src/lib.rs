use ic_crypto_internal_threshold_sig_bls12381::{
    api::{individual_public_key, sign_message, verify_individual_signature},
    ni_dkg::groth20_bls12_381::{
        compute_threshold_signing_key_univar, create_dealing,
        create_forward_secure_key_pair_el_gamal, create_transcript, verify_dealing,
    },
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
use miracl_core::bls12381::big::BIG;
use networking::Node;
use rand::Rng;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
};
use std::{fs::File, io::Write};
use tokio_stream::StreamExt;
use types::Id;

// generate key pairs for Forward Secure Encryption
pub fn generate_keypairs(n: usize) {
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[2u8, 8u8, 1u8, 2u8];

    let mut keypairs = Vec::new();
    for _ in 0..n {
        let (pk, sk) = create_forward_secure_key_pair_el_gamal(
            Randomness::from(rand::thread_rng().gen::<[u8; 32]>()),
            KEY_GEN_ASSOCIATED_DATA,
        );
        // we do tostring so that we can use serde, the BIG is not serializable by default
        keypairs.push((pk, sk.tostring()));
    }

    std::fs::write("keypairs", bincode::serialize(&keypairs).unwrap()).unwrap();
}

// setup and run the dkg
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

    let keypairs: Vec<(FsEncryptionPublicKey, String)> =
        bincode::deserialize(&std::fs::read("keypairs").expect("unable to read keypairs"))
            .expect("unable to deserialize file");

    let mut receiver_keys = BTreeMap::new();
    for (i, keypair) in keypairs.iter().enumerate() {
        receiver_keys.insert(i as u32, keypair.0);
    }

    if is_dealer {
        run_single_dealer(my_id, n, d, t, receiver_keys, addresses).await;
    } else {
        run_single_node(
            my_id,
            n,
            d,
            t,
            BIG::fromstring(keypairs[my_id].1.clone()),
            addresses,
        )
        .await;
    }
}

// run a dealer
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

    // ids we will send a message to
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

    // dealer addresses
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

    // my_id + n is the dealer. They are indexed from n..n+d
    let mut node = Node::new(addresses, Id::Univariate(my_id + n)).await;

    let total = std::time::Instant::now();

    let t1 = std::time::Instant::now();

    // generate a dealing and broadcast it
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
    let create_time = t1.elapsed();
    let mut verify_time = t1.elapsed();

    node.broadcast(bincode::serialize(&dealing).unwrap().as_slice(), dealers)
        .await;

    dealings.insert(my_id as u32, dealing);

    // wait for dealings from other nodes
    while dealings.len() < d {
        let (id, msg) = node.recv.next().await.expect("failed to read message");
        match id {
            Id::Univariate(id) => {
                if !dealings.contains_key(&((id - n) as u32)) {
                    let dealing: Dealing = bincode::deserialize(&msg).unwrap();
                    let t1 = std::time::Instant::now();
                    // verify dealing
                    verify_dealing(
                        nidkg_id,
                        (id - n) as u32,
                        threshold,
                        epoch,
                        &receiver_keys,
                        &dealing,
                    )
                    .unwrap();
                    verify_time = t1.elapsed();
                    dealings.insert((id - n) as u32, dealing);
                }
            }
            _ => (),
        }
    }

    let t1 = std::time::Instant::now();
    // combine the dealings into a transcript and broadcast it
    let transcript = create_transcript(threshold, NumberOfNodes::new(n as u32), &dealings).unwrap();
    let transcript_time = t1.elapsed();

    node.broadcast(bincode::serialize(&transcript).unwrap().as_slice(), ids)
        .await;

    // shutdown and record results
    let total_time = total.elapsed();
    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
    println!("total_time: {:?}", total_time);

    let filename = format!("results/optimized_nidkg_dealer_{}_{}", n, t);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();

    file.write_all(
        format!(
            "{:?},{:?},{:?},{:?}\n",
            total_time, create_time, verify_time, transcript_time,
        )
        .as_bytes(),
    )
    .unwrap();
}

// run a non dealer node
async fn run_single_node(
    my_id: usize,
    _n: usize,
    _d: usize,
    _t: usize,
    sk: BIG,
    addresses: BTreeMap<Id, String>,
) {
    // let total = std::time::Instant::now();
    let mut node = Node::new(addresses, Id::Univariate(my_id)).await;

    // wait for transcript
    let time = std::time::Instant::now();
    let (_, msg) = node.recv.next().await.expect("failed to read message");
    let transcript: Transcript = bincode::deserialize(&msg).unwrap();

    // recover the signing key
    let t1 = std::time::Instant::now();
    let signing_key =
        compute_threshold_signing_key_univar(transcript.receiver_data, my_id as u32, &sk).unwrap();
    let compute = t1.elapsed();

    // sign and verify signature
    let msg: [u8; 32] = [0; 32];
    let my_sig = sign_message(&msg, &signing_key).unwrap();

    verify_individual_signature(
        &msg,
        my_sig,
        individual_public_key(&transcript.public_coefficients, my_id as u32).unwrap(),
    )
    .unwrap();

    // shutdown and record results
    let total_time = time.elapsed();
    std::thread::sleep(std::time::Duration::from_secs(1));
    node.shutdown();
    println!("total_time: {:?}", total_time);

    let filename = format!("results/optimized_nidkg_{}_{}", _n, _t);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)
        .unwrap();

    file.write_all(format!("{:?},{:?}\n", total_time, compute).as_bytes())
        .unwrap();
}

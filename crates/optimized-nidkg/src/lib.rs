use ic_crypto_internal_bls12381_serde_miracl::G1Bytes;
use ic_crypto_internal_threshold_sig_bls12381::{
    api::{individual_public_key, sign_message, verify_individual_signature},
    ni_dkg::groth20_bls12_381::{
        compute_threshold_signing_key, compute_threshold_signing_key_el_gamal,
        create_dealing_el_gamal, create_forward_secure_key_pair_el_gamal, create_transcript,
        create_transcript_el_gamal, trusted_secret_key_into_miracl,
        types::{FsEncryptionKeySetWithPop, FsEncryptionSecretKey},
        verify_dealing, verify_dealing_el_gamal,
    },
    types::public_coefficients::conversions::InternalPublicCoefficients,
};
use ic_crypto_internal_types::{
    encrypt::forward_secure::groth20_bls12_381::{FsEncryptionCiphertext, FsEncryptionPublicKey},
    sign::threshold_sig::{
        ni_dkg::{
            ni_dkg_groth20_bls12_381::{Dealing, Transcript, ZKProofDec},
            Epoch,
        },
        public_key::bls12_381::PublicKeyBytes,
    },
};
use ic_crypto_internal_types::{
    sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes, NodeIndex,
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
use std::{fs::File, time::Instant};
use tokio_stream::StreamExt;
use types::bivariate::PublicCoefficients;
use types::Id;

pub fn generate_keypairs(n: usize, m: usize) {
    const KEY_GEN_ASSOCIATED_DATA: &[u8] = &[2u8, 8u8, 1u8, 2u8];

    let mut keypairs = Vec::new();
    for i in 0..n {
        keypairs.push(Vec::new());
        for _ in 0..m {
            let (pk, sk) = create_forward_secure_key_pair_el_gamal(
                Randomness::from(rand::thread_rng().gen::<[u8; 32]>()),
                KEY_GEN_ASSOCIATED_DATA,
            );
            keypairs[i].push((pk, sk.tostring()));
        }
    }

    std::fs::write("keypairs", bincode::serialize(&keypairs).unwrap()).unwrap();
}

pub async fn run_dkg(
    my_id_i: usize,
    my_id_j: usize,
    n: usize,
    m: usize,
    d: usize,
    t: usize,
    t_prime: usize,
    is_dealer: bool,
    aws: bool,
) {
    let addresses = {
        let mut addresses = BTreeMap::new();
        if aws {
            let mut reader = BufReader::new(File::open("addresses").unwrap());

            for i in 0..n {
                for j in 0..m {
                    let mut addr = String::new();
                    reader.read_line(&mut addr).unwrap();
                    addr.pop();
                    addresses.insert(Id::Bivariate(i as usize, j as usize), addr);
                }
            }

            for d in 0..d {
                let mut addr = String::new();
                reader.read_line(&mut addr).unwrap();
                addr.pop();
                addresses.insert(Id::Bivariate(n as usize, d), addr);
            }
        } else {
            let mut port = 30000;

            for i in 0..n {
                for j in 0..m {
                    addresses.insert(
                        Id::Bivariate(i as usize, j as usize),
                        format!("127.0.0.1:{}", port),
                    );
                    port += 1;
                }
            }
            for d in 0..d {
                addresses.insert(Id::Bivariate(n as usize, d), format!("127.0.0.1:{}", port));
                port += 1;
            }
        }
        addresses
    };

    let keypairs: Vec<Vec<(FsEncryptionPublicKey, String)>> =
        bincode::deserialize(&std::fs::read("keypairs").expect("unable to read keypairs"))
            .expect("unable to deserialize file");

    let mut receiver_keys = BTreeMap::new();
    for i in 0..n {
        for j in 0..m {
            receiver_keys.insert((i as u32, j as u32), keypairs[i][j].0.clone());
        }
    }

    if is_dealer {
        println!("Starting dealer");
        run_single_dealer(
            my_id_i,
            my_id_j,
            n,
            m,
            d,
            t,
            t_prime,
            receiver_keys,
            addresses,
        )
        .await;
    } else {
        println!("starting receiver");
        run_single_node(
            my_id_i,
            my_id_j,
            n,
            m,
            d,
            t,
            t_prime,
            BIG::fromstring(keypairs[my_id_i][my_id_j].1.clone()),
            addresses,
        )
        .await;
    }
}

async fn run_single_dealer(
    my_id_i: usize,
    my_id_j: usize,
    n: usize,
    m: usize,
    d: usize,
    t: usize,
    t_prime: usize,
    receiver_keys: BTreeMap<(u32, u32), FsEncryptionPublicKey>,
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
        .filter_map(|(id, _)| match id {
            Id::Bivariate(i, j) => {
                if *i == n {
                    None
                } else {
                    Some(*id)
                }
            }
            _ => None,
        })
        .collect::<Vec<Id>>();

    let dealers = addresses
        .iter()
        .filter_map(|(id, _)| match id {
            Id::Bivariate(i, idx) => {
                if *idx != my_id_j && *i == n {
                    Some(*id)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect::<Vec<Id>>();

    let keygen_seed = Randomness::from(rand::thread_rng().gen::<[u8; 32]>());
    let encryption_seed = Randomness::from(rand::thread_rng().gen::<[u8; 32]>());
    let threshold = (
        NumberOfNodes::new(t as u32),
        NumberOfNodes::new(t_prime as u32),
    );

    let mut dealings = BTreeMap::new();

    let mut node = Node::new(addresses, Id::Bivariate(my_id_i, my_id_j)).await;

    println!("Dealer creating dealings");

    let dealing = create_dealing_el_gamal(
        keygen_seed,
        encryption_seed,
        threshold,
        (n, m),
        &receiver_keys,
        epoch,
        my_id_j as u32,
        None,
    )
    .unwrap();

    dealings.insert(my_id_j as u32, (dealing.0.clone(), dealing.1.clone()));

    println!("Dealing sending dealings to: {:?}", dealers);

    node.broadcast(
        bincode::serialize(&(dealing.0.serialize(), dealing.1, dealing.2))
            .unwrap()
            .as_slice(),
        dealers,
    )
    .await;

    println!("Waiting for dealings");
    while dealings.len() < d {
        let (id, msg) = node.recv.next().await.expect("failed to read message");
        match id {
            Id::Bivariate(i, j) => {
                if !dealings.contains_key(&((j) as u32)) {
                    let dealing: (Vec<u8>, FsEncryptionCiphertext, ZKProofDec) =
                        bincode::deserialize(&msg).unwrap();
                    let dealing = (
                        PublicCoefficients::deserialize(dealing.0.clone(), t_prime),
                        dealing.1,
                        dealing.2,
                    );
                    verify_dealing_el_gamal(j as u32, threshold, epoch, &receiver_keys, &dealing)
                        .unwrap();
                    dealings.insert((j) as u32, (dealing.0, dealing.1));
                }
            }
            _ => (),
        }
    }

    println!("Making transcript");
    let transcript = create_transcript_el_gamal(
        threshold,
        (NumberOfNodes::new(n as u32), NumberOfNodes::new(m as u32)),
        &dealings,
    )
    .unwrap();

    let transcript = (transcript.0.serialize(), transcript.1);
    println!("Sent transcript");
    node.broadcast(bincode::serialize(&transcript).unwrap().as_slice(), ids)
        .await;
    std::thread::sleep(std::time::Duration::from_secs(20));
    node.shutdown();
    println!("dealer done");
}

async fn run_single_node(
    my_id_i: usize,
    my_id_j: usize,
    n: usize,
    m: usize,
    d: usize,
    t: usize,
    t_prime: usize,
    sk: BIG,
    addresses: BTreeMap<Id, String>,
) {
    let mut node = Node::new(addresses, Id::Bivariate(my_id_i, my_id_j)).await;
    println!("waiting for transcript");
    let (_, msg) = node.recv.next().await.expect("failed to read message");
    println!("got transcript");
    let transcript: (Vec<u8>, BTreeMap<NodeIndex, FsEncryptionCiphertext>) =
        bincode::deserialize(&msg).unwrap();

    let transcript = (
        PublicCoefficients::deserialize(transcript.0, t_prime),
        transcript.1,
    );

    println!("Attempting to get signing key");

    let signing_key = compute_threshold_signing_key_el_gamal(
        transcript.1,
        (my_id_i as u32, my_id_j as u32),
        (n, m),
        &sk,
    )
    .unwrap();
    println!("got my signing key");

    let msg: [u8; 32] = [0; 32];
    let my_sig = sign_message(&msg, &signing_key).unwrap();
    verify_individual_signature(
        &msg,
        my_sig,
        PublicKeyBytes::from(
            transcript
                .0
                .individual_public_key((my_id_i as u32, my_id_j as u32)),
        ),
    )
    .unwrap();
    println!("Signed message");

    std::thread::sleep(std::time::Duration::from_secs(20));
    node.shutdown();
    println!("receiver done");
}

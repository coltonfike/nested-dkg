//! Methods for forward secure encryption
use miracl_core::bls12381::pair;
use zeroize::Zeroize;

use std::collections::LinkedList;
use std::io::IoSliceMut;
use std::io::Read;
use std::vec::Vec;

// NOTE: the paper uses multiplicative notation for operations on G1, G2, GT,
// while miracl's API uses additive naming convention, hence
//    u*v  corresponds to u.add(v)
// and
//    g^x  corresponds to g.mul(x)

use crate::encryption_key_pop::{prove_pop, verify_pop, EncryptionKeyInstance, EncryptionKeyPop};
use crate::forward_secure::baby_giant;
use crate::forward_secure::Bit;
use crate::forward_secure::Crsz;
use crate::forward_secure::PublicKeyWithPop;
use crate::forward_secure::SysParam;
use crate::forward_secure::ToxicWaste;
use crate::nizk_chunking::CHALLENGE_BITS;
use crate::nizk_chunking::NUM_ZK_REPETITIONS;
use crate::random_oracles::{random_oracle, HashedMap};
use crate::utils::*;
use ic_crypto_internal_bls12381_serde_miracl::{
    miracl_fr_from_bytes, miracl_fr_to_bytes, miracl_g1_from_bytes, miracl_g1_to_bytes, FrBytes,
    G1Bytes,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::Epoch;
use lazy_static::lazy_static;
use miracl_core::bls12381::ecp::{ECP, G2_TABLE};
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::fp12::FP12;
use miracl_core::bls12381::fp4::FP4;
use miracl_core::bls12381::rom;
use miracl_core::bls12381::{big, big::BIG};
use miracl_core::rand::RAND;

const FP12_SIZE: usize = 12 * big::MODBYTES;

/// The ciphertext is an element of Fr which is 256-bits
pub const MESSAGE_BYTES: usize = 32;

/// The size in bytes of a chunk
pub const CHUNK_BYTES: usize = 2;

/// The maximum value of a chunk
pub const CHUNK_SIZE: isize = 1 << (CHUNK_BYTES << 3); // Number of distinct chunks

/// The minimum range of a chunk
pub const CHUNK_MIN: isize = 0;

/// The maximum range of a chunk
pub const CHUNK_MAX: isize = CHUNK_MIN + CHUNK_SIZE - 1;

/// NUM_CHUNKS is simply the number of chunks needed to hold a message (element
/// of Fr)
pub const NUM_CHUNKS: usize = (MESSAGE_BYTES + CHUNK_BYTES - 1) / CHUNK_BYTES;

pub fn kgen(associated_data: &[u8], rng: &mut impl RAND) -> (PublicKeyWithPop, BIG) {
    let g1 = ECP::generator();
    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);
    let spec_x = BIG::randomnum(&spec_p, rng);

    let y = g1.mul(&spec_x);

    let pop_instance = EncryptionKeyInstance {
        g1_gen: ECP::generator(),
        public_key: y.clone(),
        associated_data: associated_data.to_vec(),
    };

    let pop =
        prove_pop(&pop_instance, &spec_x, rng).expect("Implementation bug: Pop generation failed");

    (
        PublicKeyWithPop {
            key_value: y,
            proof_data: pop,
        },
        spec_x,
    )
}

pub fn enc_chunks(
    sij: &[Vec<isize>],
    pks: Vec<&ECP>,
    rng: &mut impl RAND,
) -> Vec<(G1Bytes, Vec<G1Bytes>)> {
    let spec_p = BIG::new_ints(&rom::CURVE_ORDER);
    let g1 = ECP::generator();

    sij.iter()
        .zip(pks.iter())
        .map(|(si, pk)| {
            let y = BIG::randomnum(&spec_p, rng);
            let c1 = g1.mul(&y);
            let s = pk.mul(&y);
            let c2: Vec<G1Bytes> = si
                .iter()
                .map(|s_| {
                    let mut m = g1.mul(&BIG::new_int(*s_));
                    m.add(&s);
                    miracl_g1_to_bytes(&m)
                })
                .collect();
            (miracl_g1_to_bytes(&c1), c2)
        })
        .collect()
}

pub fn dec_chunks(sk: &BIG, i: usize, ciphertext: &(G1Bytes, Vec<G1Bytes>)) -> Vec<isize> {
    // TODO: deserialize
    let c1 = miracl_g1_from_bytes(&ciphertext.0 .0).unwrap();
    let c2: Vec<ECP> = ciphertext
        .1
        .iter()
        .map(|bytes| miracl_g1_from_bytes(&bytes.0).unwrap())
        .collect();
    let ciphertext = (c1, c2);

    let g1 = ECP::generator();
    let g2 = ECP2::generator();

    let mut s = ciphertext.0.mul(sk);
    s.neg();

    // let mut c = ciphertext.1.clone();
    // let mut decrypt = Vec::new();
    // for j in 0..c.len() {
    //     c[j].add(&s);
    //     decrypt.push(c[j].clone());
    // }
    let mut c = ciphertext.1.clone();
    let mut decrypt = Vec::new();
    for j in 0..c.len() {
        c[j].add(&s);
        decrypt.push(pair::fexp(&pair::ate(&g2, &c[j])));
    }

    let base = pair::fexp(&pair::ate(&g2, &g1));
    let mut dlogs = Vec::new();

    for item in decrypt.iter() {
        match baby_giant(item, &base, 0, CHUNK_SIZE) {
            // Happy path: honest DKG participants.
            Some(dlog) => dlogs.push(BIG::new_int(dlog)),
            // It may take hours to brute force a cheater's discrete log.
            None => (),
        }
    }

    // Clippy dislikes `FrBytes::SIZE` or `MESSAGE_BYTES` instead of `32`.
    let mut fr_bytes = [0u8; 32];
    let mut big_bytes = [0u8; 48];
    let b = BIG::new_int(CHUNK_SIZE);
    let mut acc = BIG::new_int(0);
    let r = BIG::new_ints(&rom::CURVE_ORDER);
    for src in dlogs.iter() {
        acc = BIG::modadd(src, &BIG::modmul(&acc, &b, &r), &r);
    }
    acc.tobytes(&mut big_bytes);
    fr_bytes[..].clone_from_slice(&big_bytes[16..(32 + 16)]);

    // Break up fr_bytes into a vec of isize, which will be combined again later.
    // It may be better to simply return FrBytes and change enc_chunks() to take
    // FrBytes and have it break it into chunks. This would confine the chunking
    // logic to the DKG, where it belongs.
    // (I tried this for a while, but it seemed to touch a lot of code.)
    let redundant = fr_bytes[..]
        .chunks_exact(CHUNK_BYTES)
        .map(|x| 256 * (x[0] as isize) + (x[1] as isize))
        .collect();
    redundant
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::utils::RAND_ChaCha20;
    use ic_types::{
        crypto::threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet},
        Height, NumberOfNodes, PrincipalId, Randomness, SubnetId,
    };

    #[test]
    fn test_abc123() {
        let mut rng =
            RAND_ChaCha20::new(Randomness::from(rand::thread_rng().gen::<[u8; 32]>()).get());
        let keys = kgen(&[], &mut rng);

        let m: Vec<isize> = vec![0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75];
        // let (c1, c2) = enc_chunks(m, vec![&keys.0.key_value], &mut rng);

        // let recovered = dec_chunks(&keys.1, 0, (c1, c2));
        // println!("{:?}", recovered);
    }
}

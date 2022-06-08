//! Methods for forward secure encryption
use miracl_core::bls12381::pair;

use std::vec::Vec;

// NOTE: the paper uses multiplicative notation for operations on G1, G2, GT,
// while miracl's API uses additive naming convention, hence
//    u*v  corresponds to u.add(v)
// and
//    g^x  corresponds to g.mul(x)

use crate::encryption_key_pop::{prove_pop, EncryptionKeyInstance};
use crate::forward_secure::baby_giant;
use crate::forward_secure::Crsz;
use crate::forward_secure::PublicKeyWithPop;
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::ecp::ECP;
use miracl_core::bls12381::ecp2::ECP2;
use miracl_core::bls12381::rom;
use miracl_core::rand::RAND;

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

// We need a new keygen function so we can store the x directly, since the BTE keygen does not store it
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

// decrypt_chunk decrypts all chunks of a message
pub fn dec_chunks(sk: &BIG, i: usize, ciphertext: &Crsz) -> Vec<isize> {
    let c1 = &ciphertext.rr;
    let c2 = &ciphertext.cc[i];

    let g1 = ECP::generator();
    let g2 = ECP2::generator();

    let mut decrypt = Vec::new();

    for j in 0..c2.len() {
        let mut s = c1[j].mul(sk);
        s.neg();

        let mut c = c2[j].clone();

        c.add(&s);
        decrypt.push(pair::fexp(&pair::ate(&g2, &c)));
    }

    let base = pair::fexp(&pair::ate(&g2, &g1));
    let mut dlogs = Vec::new();

    for (_, item) in decrypt.iter().enumerate() {
        match baby_giant(item, &base, 0, CHUNK_SIZE) {
            // Happy path: honest DKG participants.
            Some(dlog) => dlogs.push(BIG::new_int(dlog)),
            // It may take hours to brute force a cheater's discrete log.
            None => (),
        }
        // println!("baby_giant took {:?} for chunk {}", t.elapsed(), j);
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

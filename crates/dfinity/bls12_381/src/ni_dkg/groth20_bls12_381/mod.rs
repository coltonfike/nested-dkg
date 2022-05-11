//! Non-interactive Distributed Key Generation using Groth20 with BLS12-381.
mod dealing;
mod encryption;
mod transcript;

pub mod types;

pub use dealing::{
    create_dealing, create_dealing_el_gamal, verify_dealing, verify_resharing_dealing,
};
pub use encryption::conversions::{
    public_key_into_miracl, secret_key_from_miracl, trusted_secret_key_into_miracl,
};
pub use encryption::{
    create_forward_secure_key_pair, create_forward_secure_key_pair_el_gamal,
    update_key_inplace_to_epoch,
};
pub use transcript::{
    compute_threshold_signing_key, compute_threshold_signing_key_el_gamal,
    create_resharing_transcript, create_transcript, create_transcript_el_gamal,
};

use ic_types::crypto::AlgorithmId;
const ALGORITHM_ID: AlgorithmId = AlgorithmId::NiDkg_Groth20_Bls12_381;

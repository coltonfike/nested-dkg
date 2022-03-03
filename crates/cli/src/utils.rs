use bivariate_dkg as bivariate;
use types::{
    BivariateDKGArgs, BivariateNiDKGArgs, BivariateThresholdSignatureArgs, UnivariateDKGArgs,
    UnivariateNiDKGArgs, UnivariateThresholdSignatureArgs,
};
use univariate_dkg as univariate;

pub async fn univariate_dkg(args: UnivariateDKGArgs) {
    univariate::api::run_local_dkg(args.node_index, args.num_nodes as u32, args.threshold).await;
}

pub async fn bivariate_dkg(args: BivariateDKGArgs) {
    bivariate::api::run_local_dkg(
        (args.node_index_i, args.node_index_j),
        (args.num_nodes_n as u32, args.num_nodes_m as u32),
        (args.threshold_t, args.threshold_t_prime),
    )
    .await;
}

pub fn univariate_nidkg(args: UnivariateNiDKGArgs) {
    println!("TODO: Run univariate ni dkg with args: {:?}", args);
}

pub fn bivariate_nidkg(args: BivariateNiDKGArgs) {
    println!("TODO: Run bivariate ni dkg with args: {:?}", args);
}

pub fn univariate_threshold_signature(args: UnivariateThresholdSignatureArgs) {
    println!(
        "TODO: Run univariate threshold signature with args: {:?}",
        args
    );
}

pub fn bivariate_threshold_signature(args: BivariateThresholdSignatureArgs) {
    println!(
        "TODO: Run bivariate threshold signature with args: {:?}",
        args
    );
}

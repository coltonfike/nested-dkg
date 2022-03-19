use bivariate_dkg as bivariate;
use nidkg;
use types::{
    BivariateDKGArgs, BivariateNiDKGArgs, BivariateShareFileArgs, BivariateThresholdSignatureArgs,
    NiDKGKeyPairsArgs, UnivariateDKGArgs, UnivariateNiDKGArgs, UnivariateShareFileArgs,
    UnivariateThresholdSignatureArgs,
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

pub async fn univariate_nidkg(args: UnivariateNiDKGArgs) {
    nidkg::run_local_dkg(
        args.node_index,
        args.num_nodes,
        args.num_dealers,
        args.threshold,
        args.is_dealer,
    )
    .await;
}

pub fn bivariate_nidkg(args: BivariateNiDKGArgs) {
    println!("TODO: Run bivariate ni dkg with args: {:?}", args);
}

pub fn generate_keypairs(args: NiDKGKeyPairsArgs) {
    nidkg::generate_keypairs(args.num_nodes);
}

pub async fn univariate_threshold_signature(args: UnivariateThresholdSignatureArgs) {
    univariate::api::run_local_threshold_signature(
        args.node_index,
        args.num_nodes_n as u32,
        args.threshold,
    )
    .await;
}

pub async fn bivariate_threshold_signature(args: BivariateThresholdSignatureArgs) {
    bivariate::api::run_local_threshold_signature(
        (args.node_index_i, args.node_index_j),
        (args.num_nodes_n as u32, args.num_nodes_m as u32),
        (args.threshold_t, args.threshold_t_prime),
    )
    .await;
}

pub fn univariate_share_file(args: UnivariateShareFileArgs) {
    univariate::api::write_dealing_to_file(args.num_nodes as u32, args.threshold_t);
}

pub fn bivariate_share_file(args: BivariateShareFileArgs) {
    bivariate::api::write_dealing_to_file(
        (args.num_nodes_n as u32, args.num_nodes_m as u32),
        (args.threshold_t, args.threshold_t_prime),
    );
}

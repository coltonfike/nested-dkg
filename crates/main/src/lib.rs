use bivariate_dkg as bivariate;
use nidkg;
use types::{
    BivariateDKGArgs, BivariateNiDKGArgs, BivariateNiDKGKeyPairsArgs, BivariateShareFileArgs,
    BivariateThresholdSignatureArgs, NiDKGKeyPairsArgs, UnivariateDKGArgs, UnivariateNiDKGArgs,
    UnivariateShareFileArgs, UnivariateThresholdSignatureArgs,
};
use univariate_dkg as univariate;

pub async fn univariate_dkg(args: UnivariateDKGArgs) {
    univariate::api::run_dkg(
        args.node_index,
        args.num_nodes as u32,
        args.threshold,
        args.aws,
    )
    .await;
}

pub async fn bivariate_dkg(args: BivariateDKGArgs) {
    bivariate::api::run_dkg(
        (args.node_index_i, args.node_index_j),
        (args.num_nodes_n as u32, args.num_nodes_m as u32),
        (args.threshold_t, args.threshold_t_prime),
        args.aws,
    )
    .await;
}

pub async fn univariate_nidkg(args: UnivariateNiDKGArgs) {
    if args.optimized {
        optimized_univar::run_dkg(
            args.node_index,
            args.num_nodes,
            args.num_dealers,
            args.threshold,
            args.is_dealer,
            args.aws,
        )
        .await;
    } else {
        nidkg::run_dkg(
            args.node_index,
            args.num_nodes,
            args.num_dealers,
            args.threshold,
            args.is_dealer,
            args.aws,
        )
        .await;
    }
}

pub async fn bivariate_nidkg(args: BivariateNiDKGArgs) {
    optimized_nidkg::run_dkg(
        args.node_index_i,
        args.node_index_j,
        args.num_nodes_n,
        args.num_nodes_m,
        args.num_dealers,
        args.threshold_t,
        args.threshold_t_prime,
        args.is_dealer,
        args.aws,
    )
    .await;
}

pub fn generate_keypairs(args: NiDKGKeyPairsArgs) {
    if args.optimized {
        optimized_univar::generate_keypairs(args.num_nodes);
    } else {
        nidkg::generate_keypairs(args.num_nodes);
    }
}

pub fn bivariate_generate_keypairs(args: BivariateNiDKGKeyPairsArgs) {
    optimized_nidkg::generate_keypairs(args.num_nodes_n, args.num_nodes_m);
}

pub async fn univariate_threshold_signature(args: UnivariateThresholdSignatureArgs) {
    univariate::api::run_threshold_signature(
        args.node_index,
        args.num_nodes_n as u32,
        args.threshold,
        args.aws,
    )
    .await;
}

pub async fn bivariate_threshold_signature(args: BivariateThresholdSignatureArgs) {
    bivariate::api::run_threshold_signature(
        (args.node_index_i, args.node_index_j),
        (args.num_nodes_n as u32, args.num_nodes_m as u32),
        (args.threshold_t, args.threshold_t_prime),
        args.aws,
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

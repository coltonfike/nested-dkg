use clap::Parser;
use main::*;
use types::{Cli, Command};

#[tokio::main]
async fn main() {
    let command = Cli::parse();
    match command.command {
        Command::UnivariateDKG(args) => univariate_dkg(args).await,
        Command::BivariateDKG(args) => bivariate_dkg(args).await,
        Command::UnivariateNiDKG(args) => univariate_nidkg(args.clone()),
        Command::BivariateNiDKG(args) => bivariate_nidkg(args.clone()),
        Command::UnivariateThresholdSignature(args) => univariate_threshold_signature(args.clone()),
        Command::BivariateThresholdSignature(args) => bivariate_threshold_signature(args.clone()),
    }
}

use clap::{Args, Parser, Subcommand};

// Clap structs for the different subcommands

#[derive(Parser, Clone, Debug, Eq, PartialEq)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum Command {
    UnivariateDKG(UnivariateDKGArgs),
    BivariateDKG(BivariateDKGArgs),
    UnivariateNiDKG(UnivariateNiDKGArgs),
    BivariateNiDKG(BivariateNiDKGArgs),
    NiDKGKeyPairs(NiDKGKeyPairsArgs),
    BivariateNiDKGKeyPairs(BivariateNiDKGKeyPairsArgs),
    UnivariateThresholdSignature(UnivariateThresholdSignatureArgs),
    BivariateThresholdSignature(BivariateThresholdSignatureArgs),
    UnivariateShareFile(UnivariateShareFileArgs),
    BivariateShareFile(BivariateShareFileArgs),
}

#[derive(Args, Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnivariateDKGArgs {
    // #[clap(short = 'd')]
    // num_dealers: usize,
    #[clap(short = 'i')]
    pub node_index: usize,
    #[clap(short = 'n')]
    pub num_nodes: usize,
    #[clap(short = 't')]
    pub threshold: usize,
    #[clap(short = 'a')]
    pub aws: bool,
}

#[derive(Args, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BivariateDKGArgs {
    // #[clap(short = 'd')]
    // num_dealers: usize,
    #[clap(short = 'i')]
    pub node_index_i: usize,
    #[clap(short = 'j')]
    pub node_index_j: usize,
    #[clap(short = 'n')]
    pub num_nodes_n: usize,
    #[clap(short = 'm')]
    pub num_nodes_m: usize,
    #[clap(short = 't')]
    pub threshold_t: usize,
    #[clap(short = 'p')]
    pub threshold_t_prime: usize,
    #[clap(short = 'a')]
    pub aws: bool,
}

#[derive(Args, Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnivariateNiDKGArgs {
    #[clap(short = 'i')]
    pub node_index: usize,
    #[clap(short = 'd')]
    pub num_dealers: usize,
    #[clap(short = 'n')]
    pub num_nodes: usize,
    #[clap(short = 't')]
    pub threshold: usize,
    #[clap(short = 'l')]
    pub is_dealer: bool,
    #[clap(short = 'a')]
    pub aws: bool,
    #[clap(short = 'o')]
    pub optimized: bool,
}

#[derive(Args, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BivariateNiDKGArgs {
    #[clap(short = 'd')]
    pub num_dealers: usize,
    #[clap(short = 'i')]
    pub node_index_i: usize,
    #[clap(short = 'j')]
    pub node_index_j: usize,
    #[clap(short = 'n')]
    pub num_nodes_n: usize,
    #[clap(short = 'm')]
    pub num_nodes_m: usize,
    #[clap(short = 't')]
    pub threshold_t: usize,
    #[clap(short = 'p')]
    pub threshold_t_prime: usize,
    #[clap(short = 'l')]
    pub is_dealer: bool,
    #[clap(short = 'a')]
    pub aws: bool,
    #[clap(short = 'o')]
    pub optimized: bool,
}

#[derive(Args, Clone, Copy, Debug, Eq, PartialEq)]
pub struct NiDKGKeyPairsArgs {
    #[clap(short = 'n')]
    pub num_nodes: usize,
    #[clap(short = 'o')]
    pub optimized: bool,
}

#[derive(Args, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BivariateNiDKGKeyPairsArgs {
    #[clap(short = 'n')]
    pub num_nodes_n: usize,
    #[clap(short = 'm')]
    pub num_nodes_m: usize,
    #[clap(short = 'o')]
    pub optimized: bool,
}

#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct UnivariateThresholdSignatureArgs {
    #[clap(short = 'i')]
    pub node_index: usize,
    #[clap(short = 'n')]
    pub num_nodes_n: usize,
    #[clap(short = 't')]
    pub threshold: usize,
    #[clap(short = 'a')]
    pub aws: bool,
}

#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct BivariateThresholdSignatureArgs {
    #[clap(short = 'i')]
    pub node_index_i: usize,
    #[clap(short = 'j')]
    pub node_index_j: usize,
    #[clap(short = 'n')]
    pub num_nodes_n: usize,
    #[clap(short = 'm')]
    pub num_nodes_m: usize,
    #[clap(short = 't')]
    pub threshold_t: usize,
    #[clap(short = 'p')]
    pub threshold_t_prime: usize,
    #[clap(short = 'a')]
    pub aws: bool,
}

#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct UnivariateShareFileArgs {
    #[clap(short = 'n')]
    pub num_nodes: usize,
    #[clap(short = 't')]
    pub threshold_t: usize,
}

#[derive(Args, Clone, Debug, Eq, PartialEq)]
pub struct BivariateShareFileArgs {
    #[clap(short = 'n')]
    pub num_nodes_n: usize,
    #[clap(short = 'm')]
    pub num_nodes_m: usize,
    #[clap(short = 't')]
    pub threshold_t: usize,
    #[clap(short = 'p')]
    pub threshold_t_prime: usize,
}

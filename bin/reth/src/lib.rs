#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Rust Ethereum (reth) binary executable.

pub mod chain;
pub mod cli;
pub mod config;
pub mod db;
pub mod dirs;
pub mod node;
pub mod p2p;
pub mod prometheus_exporter;
pub mod stage;
pub mod test_eth_chain;
pub use reth_cli_utils as utils;

use clap::Args;
use reth_primitives::NodeRecord;

/// Parameters for configuring the network more granularly via CLI
#[derive(Debug, Args)]
#[command(next_help_heading = "Networking")]
struct NetworkOpts {
    /// Disable the discovery service.
    #[arg(short, long)]
    disable_discovery: bool,

    /// Target trusted peer enodes
    /// --trusted-peers enode://abcd@192.168.0.1:30303
    #[arg(long)]
    trusted_peers: Vec<NodeRecord>,

    /// Connect only to trusted peers
    #[arg(long)]
    trusted_only: bool,
}
